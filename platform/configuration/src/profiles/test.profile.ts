import type { ConfigurationProfile } from './profile.js';

import { DEVELOPMENT_PROFILE } from './development.profile.js';

export const TEST_PROFILE: ConfigurationProfile = Object.freeze({
  ...DEVELOPMENT_PROFILE,
  name: 'test',
  defaults: Object.freeze({
    ...DEVELOPMENT_PROFILE.defaults,
    B89_API_PORT: '3100',
    B89_SECRET_PROVIDER_TYPE: 'test-only',
    B89_SECRET_PROVIDER_TIMEOUT: '5s',
  }),
});
