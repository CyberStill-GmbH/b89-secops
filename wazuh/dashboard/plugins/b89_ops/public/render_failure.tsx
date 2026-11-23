/* Copyright B89. SPDX-License-Identifier: Apache-2.0 */
import React from 'react';

/** A failed view must leave a visible recovery action, not an empty dashboard. */
export class ViewErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { failed: boolean }
> {
  public state = { failed: false };
  public static getDerivedStateFromError() {
    return { failed: true };
  }
  public componentDidCatch(error: Error) {
    console.error('B89 view render failed', error);
  }
  public render() {
    return this.state.failed ? (
      <section className="b89RenderFailure" role="alert" lang="es-PE">
        <h2>No se pudo abrir esta vista</h2>
        <p>La pantalla no terminó de cargar. Recarga la página; si vuelve a pasar, avisa a plataforma.</p>
        <button type="button" onClick={() => window.location.reload()}>
          Recargar página
        </button>
      </section>
    ) : (
      this.props.children
    );
  }
}

/** Handles a rejected lazy bundle before React has mounted. */
export function renderMountFailure(element: HTMLElement, error: unknown): () => void {
  console.error('B89 view load failed', error);
  const section = document.createElement('section');
  section.className = 'b89RenderFailure';
  section.setAttribute('role', 'alert');
  section.setAttribute('lang', 'es-PE');
  const title = document.createElement('h2');
  title.textContent = 'No se pudo abrir esta vista';
  const detail = document.createElement('p');
  detail.textContent =
    'La pantalla no terminó de cargar. Recarga la página; si vuelve a pasar, avisa a plataforma.';
  const retry = document.createElement('button');
  retry.type = 'button';
  retry.textContent = 'Recargar página';
  retry.onclick = () => window.location.reload();
  section.append(title, detail, retry);
  element.textContent = '';
  element.appendChild(section);
  return () => section.remove();
}
