/**
 * C-18/C-25 — endpoints de sesión del BFF.
 *
 * El navegador no ve tokens en ningún momento: `/api/auth/start` redirige al emisor,
 * `/api/auth/callback` canjea en el servidor y la única credencial que vuelve al cliente
 * es una cookie `HttpOnly` con un identificador opaco.
 *
 * El callback termina con un 303 a la consola (B-03): es una navegación del navegador y
 * no un `fetch`, así que responder con JSON dejaba a la persona frente a un documento
 * técnico. El error viaja como código público del catálogo, nunca como motivo interno.
 */

import { Body, Controller, Get, Inject, Post, Query, Req, Res } from '@nestjs/common';
import type { IncomingRequest, OutgoingReply } from '../http/http-contracts.js';

import { ApiError, signInDenialCode } from '../http/api-error.js';
import { csrfAccepted } from '../http/csrf.js';
import {
  clearSessionCookie,
  correlationIdOf,
  expiredOidcFlowCookie,
  oidcFlowBindingOf,
  originOf,
  sessionIdOf,
  setOidcFlowCookie,
  setSessionCookie,
} from '../http/request-context.js';
import { safeReturnTo, withAuthError, withSupersededNotice } from '../http/return-to.js';
import { SECOPS_RUNTIME } from './tokens.js';
import type { SecOpsRuntime } from '../runtime/secops-runtime.js';

/**
 * Una cabecera de proxy auth no puede llevar separadores ni saltos: el Security plugin la
 * parte por comas y un `\r\n` abriría otra cabecera. Solo pasan caracteres de UPN y de rol.
 */
function proxyHeaderValue(value: string): string {
  return value.replace(/[^A-Za-z0-9._@+-]/gu, '');
}

/** Rechaza una petición que el navegador marca de otro sitio o cuyo `Origin` no es el propio. */
function sameSiteRequest(request: IncomingRequest): boolean {
  const single = (value: string | readonly string[] | undefined) =>
    Array.isArray(value) ? value[0] : (value as string | undefined);
  if (single(request.headers['sec-fetch-site']) === 'cross-site') return false;
  const origin = single(request.headers.origin);
  if (origin === undefined) return true;
  const host = single(request.headers['x-forwarded-host']) ?? single(request.headers.host);
  try {
    return host !== undefined && new URL(origin).host === host;
  } catch {
    return false;
  }
}

@Controller('api/auth')
export class AuthController {
  public constructor(@Inject(SECOPS_RUNTIME) private readonly runtime: SecOpsRuntime) {}

  @Get('start')
  public async start(
    @Query() query: { returnTo?: string },
    @Req() request: IncomingRequest,
    @Res() reply: OutgoingReply,
  ) {
    const begun = await this.runtime.beginSignIn(originOf(request), safeReturnTo(query.returnTo));
    setOidcFlowCookie(reply, begun.state, begun.browserBinding, this.runtime.secureCookies);
    // 302 al emisor: el `state` queda del lado servidor, no en un campo oculto.
    const target = this.runtime.isLocalIdentity
      ? `/api/auth/local/login?state=${encodeURIComponent(begun.state)}`
      : begun.url;
    await reply
      .status(302)
      .header('cache-control', 'no-store')
      .header('referrer-policy', 'no-referrer')
      .header('location', target)
      .send();
  }

  @Get('callback')
  public async callback(
    @Query() query: { state?: string; code?: string; error?: string },
    @Req() request: IncomingRequest,
    @Res() reply: OutgoingReply,
  ) {
    const correlationId = correlationIdOf(request);
    const browserBinding = oidcFlowBindingOf(request, query.state);
    const returnTo = this.runtime.takeReturnTo(query.state, browserBinding);
    const result = await this.runtime.completeSignIn(
      { ...query, ...(browserBinding ? { browserBinding } : {}) },
      originOf(request),
      correlationId,
    );
    if (!result.ok) {
      const code = signInDenialCode(result.failure.reason);
      const expiredCookie = query.state
        ? expiredOidcFlowCookie(query.state, this.runtime.secureCookies)
        : '';
      if (expiredCookie) reply.header('set-cookie', expiredCookie);
      await reply
        .status(303)
        .header('cache-control', 'no-store')
        .header('referrer-policy', 'no-referrer')
        .header('location', withAuthError(returnTo, code, correlationId))
        .send();
      return;
    }
    setSessionCookie(
      reply,
      result.value.session.id,
      this.runtime.secureCookies,
      Math.floor(
        (result.value.session.absoluteExpiresAt.getTime() - this.runtime.now().getTime()) / 1000,
      ),
      query.state
        ? [expiredOidcFlowCookie(query.state, this.runtime.secureCookies)].filter(Boolean)
        : [],
    );
    await reply
      .status(303)
      .header('cache-control', 'no-store')
      .header('referrer-policy', 'no-referrer')
      .header('location', withSupersededNotice(returnTo, result.value.supersededSessions.length))
      .send();
  }

  /**
   * Acceso con usuario y contraseña desde el formulario del login. Responde como el callback:
   * 303 al destino con la cookie de sesión, o al mismo destino con el código público del
   * catálogo. Funciona como `application/x-www-form-urlencoded` (sin JavaScript) y como JSON.
   *
   * Como todavía no hay sesión que lleve un token CSRF, el formulario se protege contra el
   * *login CSRF* (que otro sitio inicie sesión a la víctima con la cuenta del atacante)
   * rechazando peticiones de otro sitio por `Sec-Fetch-Site` y por `Origin`.
   */
  @Post('password')
  public async password(
    @Body() body: { username?: unknown; password?: unknown; returnTo?: unknown } | undefined,
    @Req() request: IncomingRequest,
    @Res() reply: OutgoingReply,
  ) {
    const correlationId = correlationIdOf(request);
    const returnTo = safeReturnTo(body?.returnTo);
    const fail = async (code: string) => {
      await reply
        .status(303)
        .header('cache-control', 'no-store')
        .header('referrer-policy', 'no-referrer')
        .header('location', withAuthError(returnTo, code, correlationId))
        .send();
    };
    if (!sameSiteRequest(request)) {
      await fail('REQUEST_NOT_VERIFIED');
      return;
    }
    const username = typeof body?.username === 'string' ? body.username : '';
    const password = typeof body?.password === 'string' ? body.password : '';
    if (username.length === 0 || password.length === 0) {
      await fail('AUTH_FAILED');
      return;
    }
    const result = await this.runtime.passwordSignIn(
      { username, password, returnTo },
      originOf(request),
      correlationId,
    );
    const flowCookie = result.flow
      ? expiredOidcFlowCookie(result.flow.state, this.runtime.secureCookies)
      : '';
    if (!result.ok) {
      if (flowCookie) reply.header('set-cookie', flowCookie);
      await fail(signInDenialCode(result.failure.reason));
      return;
    }
    setSessionCookie(
      reply,
      result.value.session.id,
      this.runtime.secureCookies,
      Math.floor(
        (result.value.session.absoluteExpiresAt.getTime() - this.runtime.now().getTime()) / 1000,
      ),
      [flowCookie].filter(Boolean),
    );
    await reply
      .status(303)
      .header('cache-control', 'no-store')
      .header('referrer-policy', 'no-referrer')
      .header(
        'location',
        withSupersededNotice(result.flow.returnTo, result.value.supersededSessions.length),
      )
      .send();
  }

  @Get('session')
  public async session(@Req() request: IncomingRequest) {
    const correlationId = correlationIdOf(request);
    const resolved = await this.runtime.resolveActor(sessionIdOf(request), originOf(request));
    if (!resolved.ok) throw new ApiError(resolved.reason, correlationId);
    return {
      subjectId: resolved.actor.subjectId,
      displayName: resolved.session.displayName ?? null,
      email: resolved.session.email ?? null,
      tenantId: resolved.actor.tenantId,
      roles: resolved.actor.roles,
      capabilities: [...resolved.actor.capabilities].sort(),
      amr: resolved.session.amr,
      // Solo legible desde el mismo origen (no hay CORS); se reenvía en `x-csrf-token`.
      csrfToken: this.runtime.csrfTokenFor(resolved.session.id),
      correlationId,
    };
  }

  /**
   * Introspección para el proxy del dashboard SOC (nginx `auth_request`).
   *
   * El dashboard (fork de OpenSearch Dashboards) no tiene login propio: confía en esta
   * misma sesión. El proxy pregunta aquí en cada navegación y, con 204, inyecta la persona
   * y sus roles B89 como cabeceras de *proxy auth* hacia el Security plugin. Sin cuerpo:
   * `auth_request` solo lee estado y cabeceras. Los fallos reutilizan el catálogo (401/403).
   */
  @Get('introspect')
  public async introspect(@Req() request: IncomingRequest, @Res() reply: OutgoingReply) {
    const correlationId = correlationIdOf(request);
    const resolved = await this.runtime.resolveActor(sessionIdOf(request), originOf(request));
    if (!resolved.ok) throw new ApiError(resolved.reason, correlationId);
    await reply
      .status(204)
      .header('cache-control', 'no-store')
      .header('x-b89-user', proxyHeaderValue(resolved.session.email ?? resolved.actor.subjectId))
      .header('x-b89-roles', resolved.actor.roles.map(proxyHeaderValue).join(','))
      .header('x-correlation-id', correlationId)
      .send();
  }

  @Post('logout')
  public async logout(@Req() request: IncomingRequest, @Res() reply: OutgoingReply) {
    const correlationId = correlationIdOf(request);
    const resolved = await this.runtime.resolveActor(sessionIdOf(request), originOf(request));
    // Una sesión vigente solo se cierra con su token: otro sitio no puede expulsar a la
    // persona. Sin sesión vigente no hay nada que proteger y la cookie se limpia igual.
    if (resolved.ok) {
      if (!csrfAccepted(request, this.runtime.csrfTokenFor(resolved.session.id))) {
        throw new ApiError('REQUEST_NOT_VERIFIED', correlationId);
      }
      await this.runtime.signOut(resolved.session.id);
    }
    clearSessionCookie(reply, this.runtime.secureCookies);
    await reply.status(204).send();
  }
}
