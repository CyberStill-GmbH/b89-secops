# Bunny: asistente IA del SOC (la lógica vive en la app; aquí solo permisos, red y config).
#
# Red: este stack NO tiene NAT, así que la Lambda api (en VPC) no sale a Internet.
# - bunny_provider = "bedrock" (recomendado): la app usa el cliente Mantle de Bedrock con IDs
#   "anthropic.<modelo>" y llega a Bedrock por los endpoints de interfaz listados en
#   bunny_bedrock_endpoint_services (por defecto bedrock-runtime). Si el cliente Mantle usa un
#   endpoint distinto, añadir su servicio de endpoint de VPC a esa lista (no verificado aquí).
#   El acceso al modelo debe habilitarse en la consola de Bedrock de la cuenta/región.
# - bunny_provider = "anthropic": API directa de Anthropic; SOLO funciona si el operador añade
#   salida a Internet (NAT o proxy) y declara bunny_internet_egress_available = true. La API key
#   se carga a mano en el secreto contenedor .../bunny/anthropic-api-key.

resource "aws_secretsmanager_secret" "bunny_anthropic" {
  count = local.bunny_anthropic ? 1 : 0

  name                    = "${local.ssm_prefix}/bunny/anthropic-api-key"
  description             = "API key de Anthropic para Bunny. Contenedor sin valor: la carga el dueño."
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = local.is_prod ? 30 : 0
}

locals {
  bunny_resource_arns = flatten([for id in local.bunny_model_ids : [
    "arn:${local.partition}:bedrock:*::foundation-model/${id}*",
    "arn:${local.partition}:bedrock:*:${local.account_id}:inference-profile/*${id}*",
  ]])

  bunny_statements = concat(
    local.bunny_bedrock ? [{
      sid        = "BunnyBedrockInvoke"
      effect     = "Allow"
      actions    = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      resources  = local.bunny_resource_arns
      conditions = []
    }] : [],
    local.bunny_anthropic ? [{
      sid        = "BunnyAnthropicKey"
      effect     = "Allow"
      actions    = ["secretsmanager:GetSecretValue"]
      resources  = [aws_secretsmanager_secret.bunny_anthropic[0].arn]
      conditions = []
    }] : [],
  )

  bunny_env = {
    B89_BUNNY_ENABLED            = tostring(var.enable_bunny)
    B89_BUNNY_PROVIDER           = var.bunny_provider
    B89_BUNNY_MODEL              = var.enable_bunny ? local.bunny_model_id : ""
    B89_BUNNY_API_KEY_SECRET_ARN = local.bunny_anthropic ? aws_secretsmanager_secret.bunny_anthropic[0].arn : ""
    B89_BUNNY_REDACT_PII         = tostring(var.bunny_redact_pii)
    B89_BUNNY_EFFORT             = var.bunny_effort
  }
}

# Aviso (no bloqueante) si la configuración no puede funcionar por red.
check "bunny_network_path" {
  assert {
    condition     = !local.bunny_anthropic || var.bunny_internet_egress_available
    error_message = "bunny_provider = \"anthropic\" requiere salida a Internet desde las subredes privadas y este stack no tiene NAT. Usa bunny_provider = \"bedrock\" o añade NAT/proxy y declara bunny_internet_egress_available = true."
  }

  assert {
    condition     = !local.bunny_bedrock || var.enable_interface_endpoints
    error_message = "Bunny con Bedrock necesita enable_interface_endpoints = true (endpoint de bedrock-runtime) porque las Lambdas no tienen salida a Internet."
  }
}

check "lambda_vpc_reachability" {
  assert {
    condition     = var.enable_interface_endpoints
    error_message = "Con enable_interface_endpoints = false las Lambdas en VPC no alcanzan Secrets Manager, SSM, Step Functions ni SQS (no hay NAT). Úsalo solo para entornos efímeros o añade salida propia."
  }
}
