/**
 * Conocimiento estático de Bunny (docs/17 · ingeniería de detección), empaquetado en la imagen de
 * la API al compilar: runbooks de triage, playbooks de B89 Respond, reglas B89 con su mapeo MITRE
 * ATT&CK y casos de uso. Lo genera `apps/api/scripts/generate-bunny-knowledge.py` a partir de
 * `docs/detection-engineering/` y `detections/`; aquí solo están los tipos y las búsquedas.
 *
 * Es documentación interna del SOC, no datos de clientes: cualquier persona que pueda usar a Bunny
 * puede consultarla (igual que el repositorio de runbooks).
 */

export interface KnowledgeRunbook {
  readonly id: string;
  readonly title: string;
  readonly path: string;
  readonly sections: readonly string[];
  readonly ruleIds: readonly string[];
  readonly useCases: readonly string[];
  readonly markdown: string;
}

export interface KnowledgeUseCase {
  readonly id: string;
  readonly title: string;
  readonly source: string;
  readonly useCase: string;
  readonly status: string;
  readonly ruleIds: readonly string[];
  readonly mitre: readonly string[];
  readonly priorityHint?: string | null;
  readonly falsePositives: readonly string[];
  readonly dataSources: readonly string[];
}

export interface KnowledgeRule {
  readonly id: string;
  readonly level: number;
  readonly description: string;
  readonly mitre: readonly string[];
  readonly groups: readonly string[];
  readonly file: string;
  readonly useCases?: readonly string[];
  readonly runbooks?: readonly string[];
}

export interface KnowledgeTechnique {
  readonly name: string;
  readonly tactics: readonly { readonly id: string; readonly name: string }[];
}

export interface SocKnowledge {
  readonly attackVersion: string;
  readonly runbookIndex: string;
  readonly playbooks: string;
  readonly runbooks: readonly KnowledgeRunbook[];
  readonly useCases: readonly KnowledgeUseCase[];
  readonly rules: Readonly<Record<string, KnowledgeRule>>;
  readonly techniques: Readonly<Record<string, KnowledgeTechnique>>;
}

/** Normaliza para buscar sin tildes ni mayúsculas. */
export function fold(text: string): string {
  return text
    .normalize('NFD')
    .replace(/[̀-ͯ]/gu, '')
    .toLocaleLowerCase('es');
}

export function techniqueView(knowledge: SocKnowledge, id: string) {
  const technique = knowledge.techniques[id];
  return {
    id,
    name: technique?.name ?? null,
    tactics: technique?.tactics ?? [],
    url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
  };
}

/** Regla B89 con su contexto: técnicas, casos de uso, falsos positivos y runbooks. */
export function ruleView(knowledge: SocKnowledge, rule: KnowledgeRule) {
  const useCases = (rule.useCases ?? [])
    .map((id) => knowledge.useCases.find((useCase) => useCase.id === id))
    .filter((useCase): useCase is KnowledgeUseCase => useCase !== undefined);
  return {
    ruleId: rule.id,
    level: rule.level,
    description: rule.description,
    file: rule.file,
    mitre: rule.mitre.map((id) => techniqueView(knowledge, id)),
    useCases: useCases.map((useCase) => ({
      id: useCase.id,
      title: useCase.title,
      status: useCase.status,
      priorityHint: useCase.priorityHint ?? null,
      falsePositives: useCase.falsePositives,
      dataSources: useCase.dataSources,
    })),
    runbooks: (rule.runbooks ?? []).map((id) => {
      const runbook = knowledge.runbooks.find((entry) => entry.id === id);
      return { id, title: runbook?.title ?? id, path: runbook?.path ?? null };
    }),
  };
}

/**
 * Regla cuya descripción coincide con el título de una alerta. Los títulos son la descripción de la
 * regla con las variables `$(campo)` ya sustituidas: se compara el prefijo fijo más largo.
 */
export function ruleForTitle(knowledge: SocKnowledge, title: string): KnowledgeRule | undefined {
  const target = fold(title);
  let best: { rule: KnowledgeRule; score: number } | undefined;
  for (const rule of Object.values(knowledge.rules)) {
    const fixed = fold(rule.description.split('$(')[0] ?? '').trim();
    if (fixed.length < 12 || !target.startsWith(fixed)) continue;
    if (!best || fixed.length > best.score) best = { rule, score: fixed.length };
  }
  return best?.rule;
}

/** Técnicas cuyo id o nombre coincide con el texto. */
export function findTechniques(knowledge: SocKnowledge, query: string) {
  const q = fold(query.trim());
  return Object.keys(knowledge.techniques)
    .filter((id) => fold(id) === q || fold(id).startsWith(`${q}.`) || fold(knowledge.techniques[id]?.name ?? '').includes(q))
    .slice(0, 10);
}

/** Reglas B89 que implementan una técnica (incluye subtécnicas). */
export function rulesForTechnique(knowledge: SocKnowledge, technique: string): KnowledgeRule[] {
  return Object.values(knowledge.rules).filter((rule) =>
    rule.mitre.some((id) => id === technique || id.startsWith(`${technique}.`)),
  );
}

/** Puntúa runbooks por términos de la consulta (título, alcance, reglas y cuerpo). */
export function searchRunbooks(knowledge: SocKnowledge, query: string): KnowledgeRunbook[] {
  const terms = fold(query)
    .split(/[^a-z0-9.]+/u)
    .filter((term) => term.length >= 3);
  if (terms.length === 0) return [];
  return knowledge.runbooks
    .map((runbook) => {
      const title = fold(`${runbook.id} ${runbook.title}`);
      const body = fold(runbook.markdown);
      let score = 0;
      for (const term of terms) {
        if (runbook.ruleIds.includes(term)) score += 6;
        if (title.includes(term)) score += 4;
        if (body.includes(term)) score += 1;
      }
      return { runbook, score };
    })
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((entry) => entry.runbook);
}

