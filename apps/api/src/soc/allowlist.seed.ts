/**
 * Lista blanca inicial de la API de pagos, importada de «Whitelist_IPs_Clientes_B89.xlsx»
 * (hojas Seguimiento y Proveedores, 2026-11-23). Solo se usa mientras no exista una versión guardada.
 * Las IPs que perdieron los puntos quedan en la nota como «por reconfirmar»: no se vigilan.
 */

export const ALLOWLIST_SEED: unknown[] = [
  {
    "id": "bpc-1-payouts-peru",
    "name": "BPC 1",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "34.199.50.40"
    ],
    "sandboxIps": [
      "3.126.133.76",
      "18.198.16.14"
    ],
    "markers": [],
    "note": "No hay necesidad · Reconfirmar IP prod que perdió los puntos · IPs por reconfirmar (no se vigilan): 4421486220"
  },
  {
    "id": "bpc-2-payouts-peru",
    "name": "BPC 2",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "34.199.50.40"
    ],
    "sandboxIps": [
      "3.126.133.76",
      "18.198.16.14"
    ],
    "markers": [],
    "note": "No hay necesidad · Confirmar que las IPs de BPC aplican a ambas cuentas · IPs por reconfirmar (no se vigilan): 4421486220"
  },
  {
    "id": "organic-fit-payouts-peru",
    "name": "Organic & Fit",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad, subida de archivos · Validar acceso si el panel también deja de ser público"
  },
  {
    "id": "terrapay-payouts-peru",
    "name": "Terrapay",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "54.76.150.47"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": null
  },
  {
    "id": "murkon-payouts-bolivia",
    "name": "Murkon",
    "kind": "client",
    "product": "Payouts",
    "country": "Bolivia",
    "company": "B89 SA",
    "status": "with_ip",
    "prodIps": [
      "185.5.127.50"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": null
  },
  {
    "id": "corporacion-nutraclinic-payouts-peru",
    "name": "Corporación Nutraclinic",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad, subida de archivos · Validar acceso si el panel también deja de ser público"
  },
  {
    "id": "b2-payouts-peru",
    "name": "B2",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad, subida de archivos · Validar acceso si el panel también deja de ser público"
  },
  {
    "id": "thunes-payouts-peru",
    "name": "Thunes",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "52.209.198.21"
    ],
    "sandboxIps": [
      "52.210.98.87"
    ],
    "markers": [],
    "note": "Respondió, derivó a otra persona interna · Reconfirmar IP sandbox que perdió los puntos · IPs por reconfirmar (no se vigilan): 52209246249"
  },
  {
    "id": "tap-tap-send-payouts-peru",
    "name": "Tap Tap Send",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "52.2.191.196",
      "3.208.171.37"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": "Actualizar estado en el mapeo TECH"
  },
  {
    "id": "pmi-americas-payouts-peru",
    "name": "PMI Americas",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "paypros-payouts-peru",
    "name": "Paypros",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "bamboo-payouts-peru",
    "name": "Bamboo",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "banexcoin-payouts-peru",
    "name": "Banexcoin",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "35.184.109.7"
    ],
    "sandboxIps": [
      "35.184.109.7"
    ],
    "markers": [],
    "note": null
  },
  {
    "id": "vitawallet-payouts-peru",
    "name": "Vitawallet",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "35.193.250.68"
    ],
    "sandboxIps": [
      "34.29.245.116"
    ],
    "markers": [],
    "note": "Respondió, derivó a otra persona interna · Hacer seguimiento con el nuevo contacto"
  },
  {
    "id": "maxisend-payouts-peru",
    "name": "Maxisend",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "54.203.107.95",
      "23.23.23.180"
    ],
    "sandboxIps": [
      "135.148.75.84"
    ],
    "markers": [],
    "note": null
  },
  {
    "id": "maxisend-payouts-venezuela",
    "name": "Maxisend",
    "kind": "client",
    "product": "Payouts",
    "country": "Venezuela",
    "company": "B89 SA",
    "status": "with_ip",
    "prodIps": [
      "54.203.107.95",
      "23.23.23.180"
    ],
    "sandboxIps": [
      "135.148.75.84"
    ],
    "markers": [],
    "note": "Confirmar que las IPs aplican también a Venezuela"
  },
  {
    "id": "echange-payouts-peru",
    "name": "Echange",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "transfast-payouts-peru",
    "name": "Transfast",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "alfredpay-payouts-peru",
    "name": "Alfredpay",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "Sin estado (–) · Sin operaciones desde 30/06/2026: confirmar si sigue activo"
  },
  {
    "id": "cp-money-transfer-payouts-peru",
    "name": "CP Money Transfer",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "remitee-payouts-peru",
    "name": "Remitee",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad, whitelisted en Ripple"
  },
  {
    "id": "more-payouts-peru",
    "name": "More",
    "kind": "client",
    "product": "Payouts",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "more-payouts-bolivia",
    "name": "More",
    "kind": "client",
    "product": "Payouts",
    "country": "Bolivia",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "cambios-app-payouts-colombia",
    "name": "Cambios APP",
    "kind": "client",
    "product": "Payouts",
    "country": "Colombia",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "paypros-payins-peru",
    "name": "Paypros",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad"
  },
  {
    "id": "paypros-brasil-payins-brasil",
    "name": "Paypros Brasil",
    "kind": "client",
    "product": "Payins",
    "country": "Brasil",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Confirmar si comparte integración con Paypros Perú"
  },
  {
    "id": "banexcoin-payins-peru",
    "name": "Banexcoin",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "35.184.109.7"
    ],
    "sandboxIps": [
      "35.184.109.7"
    ],
    "markers": [],
    "note": null
  },
  {
    "id": "cuibu-payins-venezuela",
    "name": "Cuibu",
    "kind": "client",
    "product": "Payins",
    "country": "Venezuela",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "vendis-payins-peru",
    "name": "Vendis",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "pending",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "pagodirecto-payins-peru",
    "name": "Pagodirecto",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No es cliente · Solicitar IPs"
  },
  {
    "id": "flexifai-payins-peru",
    "name": "Flexifai",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "flexifai-payins-bolivia",
    "name": "Flexifai",
    "kind": "client",
    "product": "Payins",
    "country": "Bolivia",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "lernymart-payins-peru",
    "name": "Lernymart",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "versotek-payins-peru",
    "name": "Versotek",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "tegrix-payins-bolivia",
    "name": "Tegrix",
    "kind": "client",
    "product": "Payins",
    "country": "Bolivia",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No es cliente · Solicitar IPs"
  },
  {
    "id": "xtranfer-payins-peru",
    "name": "Xtranfer",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No es cliente · Solicitar IPs"
  },
  {
    "id": "xtranfer-payins-bolivia",
    "name": "Xtranfer",
    "kind": "client",
    "product": "Payins",
    "country": "Bolivia",
    "company": "B89 SA",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No es cliente · Solicitar IPs"
  },
  {
    "id": "odl-abogados-payins-peru",
    "name": "ODL Abogados",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No figura en el mapeo · Solicitar IPs"
  },
  {
    "id": "core-do-brasil-payins-peru",
    "name": "Core do Brasil",
    "kind": "client",
    "product": "Payins",
    "country": "Perú",
    "company": "B89 Payments",
    "status": "with_ip",
    "prodIps": [
      "52.207.221.34"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": "Sin estado (–) · IP de salida del backend OnZap/CORE"
  },
  {
    "id": "antilla-capital-payins",
    "name": "Antilla Capital",
    "kind": "client",
    "product": "Payins",
    "country": null,
    "company": null,
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No hay necesidad · No figura en la lista general de clientes: confirmar"
  },
  {
    "id": "prov-gmoney",
    "name": "Gmoney",
    "kind": "provider",
    "product": "Payin / Payout",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [
      "54.174.6.8"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": null
  },
  {
    "id": "prov-chinchin",
    "name": "Chinchin",
    "kind": "provider",
    "product": "Payin / Payout",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [],
    "sandboxIps": [
      "200.74.205.170"
    ],
    "markers": [],
    "note": "Reconfirmar ambas IPs · IPs por reconfirmar (no se vigilan): 20074205162"
  },
  {
    "id": "prov-banexcoin",
    "name": "Banexcoin",
    "kind": "provider",
    "product": "Payin / Payout",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [
      "35.184.109.7"
    ],
    "sandboxIps": [
      "35.184.109.7"
    ],
    "markers": [],
    "note": null
  },
  {
    "id": "prov-murkon",
    "name": "Murkon",
    "kind": "provider",
    "product": "Payout / Tipo de cambio",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [
      "185.5.127.50"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": null
  },
  {
    "id": "prov-qrpay",
    "name": "Qrpay",
    "kind": "provider",
    "product": "Payin",
    "country": null,
    "company": null,
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "Ya no es proveedor · Hacer seguimiento con el nuevo contacto"
  },
  {
    "id": "prov-bcp",
    "name": "Bcp",
    "kind": "provider",
    "product": "Payout (integración)",
    "country": null,
    "company": null,
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No comparte IP · Definir control alternativo (p. ej., firma de webhook / mTLS)"
  },
  {
    "id": "prov-monnet",
    "name": "Monnet",
    "kind": "provider",
    "product": "Payin / Payout",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [
      "18.214.182.8",
      "54.144.19.212"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": "Validar si envía webhooks/callbacks a B89"
  },
  {
    "id": "prov-paysafe",
    "name": "Paysafe",
    "kind": "provider",
    "product": "Payin",
    "country": null,
    "company": null,
    "status": "not_required",
    "prodIps": [],
    "sandboxIps": [],
    "markers": [],
    "note": "No es proveedor · Validar si envía webhooks/callbacks a B89"
  },
  {
    "id": "prov-rextie-v2",
    "name": "Rextie_V2",
    "kind": "provider",
    "product": "Payout / Tipo de cambio",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [
      "44.214.228.96",
      "52.204.119.242"
    ],
    "sandboxIps": [
      "107.22.104.88",
      "52.6.242.29"
    ],
    "markers": [],
    "note": "Validar si envía webhooks/callbacks a B89"
  },
  {
    "id": "prov-datatec",
    "name": "Datatec",
    "kind": "provider",
    "product": "Tipo de cambio (WebSocket)",
    "country": null,
    "company": null,
    "status": "with_ip",
    "prodIps": [
      "200.60.106.86",
      "200.60.106.87",
      "200.37.151.5",
      "200.37.151.25",
      "190.81.168.51",
      "190.81.168.52"
    ],
    "sandboxIps": [],
    "markers": [],
    "note": "Conexión saliente: validar si requiere regla de entrada"
  }
];
