/**
 * Adaptador del puerto `AssistantModel` hacia Claude. Usa el SDK oficial: el cliente de Anthropic
 * (`anthropic`) o el de Amazon Bedrock Mantle (`bedrock`); ambos exponen `messages.create`.
 *
 * Decisiones:
 * - Sin streaming: API Gateway HTTP almacena la respuesta completa; el tiempo total lo acota el
 *   bucle del dominio (`deadlineMs`) y cada llamada lleva `AbortSignal`.
 * - Pensamiento adaptativo (por omisión en los modelos actuales) y profundidad con `effort`; no se
 *   usan `temperature`, prefill ni `tool_choice` forzado (no soportados en estos modelos).
 * - Una negativa del modelo (`refusal`) se devuelve como tal; el dominio la comunica sin inventar.
 */

import Anthropic from '@anthropic-ai/sdk';
import { AnthropicBedrockMantle } from '@anthropic-ai/bedrock-sdk';
import type {
  AssistantModel,
  ConversationMessage,
  ModelBlock,
  ModelRequest,
  ModelResponse,
  ModelStopReason,
} from '@b89/assistant';

import type { AssistantConfig } from './assistant-config.js';

type EnabledConfig = Extract<AssistantConfig, { enabled: true }>;

/** Superficie mínima de `messages.create` que usa el adaptador (permite probarlo sin red). */
export interface MessagesClient {
  messages: {
    create(
      params: Anthropic.MessageCreateParamsNonStreaming,
      options?: { signal?: AbortSignal },
    ): Promise<Anthropic.Message>;
  };
}

export function createMessagesClient(config: EnabledConfig): MessagesClient {
  if (config.provider === 'anthropic') {
    return new Anthropic({ apiKey: config.apiKey, maxRetries: 1 }) as unknown as MessagesClient;
  }
  return new AnthropicBedrockMantle({
    awsRegion: config.awsRegion,
    maxRetries: 1,
  }) as unknown as MessagesClient;
}

function toParam(message: ConversationMessage): Anthropic.MessageParam {
  if (typeof message.content === 'string') return { role: message.role, content: message.content };
  return {
    role: message.role,
    content: message.content.map((block): Anthropic.ContentBlockParam => {
      if (block.type === 'text') return { type: 'text', text: block.text };
      if (block.type === 'tool_use') {
        return { type: 'tool_use', id: block.id, name: block.name, input: block.input };
      }
      if (block.type === 'thinking') {
        return { type: 'thinking', thinking: block.thinking, signature: block.signature };
      }
      if (block.type === 'redacted_thinking')
        return { type: 'redacted_thinking', data: block.data };
      return {
        type: 'tool_result',
        tool_use_id: block.tool_use_id,
        content: block.content,
        ...(block.is_error ? { is_error: true } : {}),
      };
    }),
  };
}

function stopReasonOf(reason: Anthropic.Message['stop_reason']): ModelStopReason {
  switch (reason) {
    case 'end_turn':
    case 'tool_use':
    case 'max_tokens':
    case 'refusal':
      return reason;
    default:
      return 'other';
  }
}

export function createClaudeModel(
  config: EnabledConfig,
  client: MessagesClient = createMessagesClient(config),
): AssistantModel {
  return {
    async complete(request: ModelRequest, signal?: AbortSignal): Promise<ModelResponse> {
      const response = await client.messages.create(
        {
          model: config.model,
          max_tokens: request.maxTokens,
          system: [{ type: 'text', text: request.system, cache_control: { type: 'ephemeral' } }],
          messages: request.messages.map(toParam),
          tools: request.tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            input_schema: tool.inputSchema as Anthropic.Tool.InputSchema,
          })),
          ...(request.allowTools ? {} : { tool_choice: { type: 'none' as const } }),
          // Resúmenes de razonamiento visibles para la persona (por omisión vienen vacíos).
          thinking: { type: 'adaptive' as const, display: 'summarized' as const },
          output_config: { effort: config.effort },
        },
        signal ? { signal } : undefined,
      );
      const content: ModelBlock[] = [];
      for (const block of response.content) {
        if (block.type === 'text') content.push({ type: 'text', text: block.text });
        else if (block.type === 'thinking') {
          content.push({ type: 'thinking', thinking: block.thinking, signature: block.signature });
        } else if (block.type === 'redacted_thinking') {
          content.push({ type: 'redacted_thinking', data: block.data });
        } else if (block.type === 'tool_use') {
          content.push({
            type: 'tool_use',
            id: block.id,
            name: block.name,
            input: (block.input ?? {}) as Record<string, unknown>,
          });
        }
      }
      return {
        content,
        stopReason: stopReasonOf(response.stop_reason),
        usage: {
          inputTokens: response.usage.input_tokens,
          outputTokens: response.usage.output_tokens,
        },
      };
    },
  };
}
