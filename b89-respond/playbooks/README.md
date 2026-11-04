# b89-respond/playbooks · Playbooks exportables de B89 Respond

Diseño, prerrequisitos y estado: [docs/detection-engineering/04](../../docs/detection-engineering/04-playbooks-b89-respond.md).

| Archivo | Qué hace | Efectos | Aprobación |
| --- | --- | --- | --- |
| `b89-triage-enriquecimiento.json` | Valida y deduplica la alerta, lee la prioridad B89 y el agente, deja nota y avisa por correo B89 | Nota y correo | No (solo lectura) |
| `b89-contencion-identidad-aprobada.json` | Revoca sesiones y deshabilita la cuenta de Entra | Alto | Líder SOC + step-up, SoD |
| `b89-contencion-endpoint-aprobada.json` | `firewall-drop` 600 s en el agente Linux | Medio | Líder SOC, SoD |

**Requieren aprobación de B89 antes de importarlos.** La contención trae `b89_contencion_habilitada = false`
y una compuerta que exige aprobador distinto del solicitante; los webhooks se exportan detenidos y las
credenciales son referencias a autenticaciones del almacén cifrado, nunca valores. Prueba de contrato:

```bash
node --test b89-respond/playbooks/playbooks.test.mjs
```
