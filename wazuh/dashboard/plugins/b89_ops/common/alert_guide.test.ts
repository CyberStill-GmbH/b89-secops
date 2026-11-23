import { describe, expect, it } from 'vitest';
import { GUIDED_RULE_IDS, guideForAlertTitle, guideForRule } from './alert_guide';

describe('alert guide', () => {
  it('explains a stolen-credential alert from its title, with steps to confirm and act', () => {
    const guide = guideForAlertTitle(
      'B89 Cloudflare: credencial del backoffice de pagos usada desde hosting/VPN (wazuh 101531)',
    );
    expect(guide?.urgency).toBe('act');
    expect(guide?.headline).toMatch(/backoffice/u);
    expect(guide?.isItReal.length).toBeGreaterThan(0);
    expect(guide?.whatToDo.length).toBeGreaterThan(0);
  });

  it('separates attacks that hit the app from those Cloudflare stopped', () => {
    expect(guideForRule('102009')?.urgency).toBe('act');
    expect(guideForRule('102010')?.urgency).toBe('info');
    expect(guideForRule('101539')?.whatHappened).toMatch(/no llegó/u);
  });

  it('returns null when there is no specific guide (no invented explanation)', () => {
    expect(guideForAlertTitle('B89 Snyk: hallazgo (wazuh 101451)')).toBeNull();
    expect(guideForAlertTitle('Sin regla')).toBeNull();
    expect(guideForRule(null)).toBeNull();
  });

  it('every guide is complete and readable', () => {
    for (const id of GUIDED_RULE_IDS) {
      const guide = guideForRule(id)!;
      expect(guide.headline.length, id).toBeGreaterThan(10);
      expect(guide.whatHappened.length, id).toBeGreaterThan(20);
      expect(guide.isItReal.length, id).toBeGreaterThan(0);
      expect(guide.whatToDo.length, id).toBeGreaterThan(0);
    }
  });
});
