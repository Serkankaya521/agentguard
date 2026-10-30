// Finding lifecycle transitions shared by the findings list and finding detail.
// Mirrors the server's allowed workflow so only valid actions are shown; the API
// still enforces it. The second element of each tuple is an i18n key.
// Kept in lib (not a page module) so both pages can import it without
// cross-importing a route file.
export const NEXT: Record<string, [string, string][]> = {
  SUSPECTED: [['VALIDATING', 'tr.validate'], ['FALSE_POSITIVE', 'tr.falsePositive']],
  VALIDATING: [['CONFIRMED', 'tr.confirm'], ['FALSE_POSITIVE', 'tr.falsePositive']],
  CONFIRMED: [['FIX_PROPOSED', 'tr.fixProposed'], ['FALSE_POSITIVE', 'tr.falsePositive']],
  FIX_PROPOSED: [['RETESTING', 'tr.startRetest']],
  REOPENED: [['FIX_PROPOSED', 'tr.fixProposed'], ['RETESTING', 'tr.startRetest']],
  FALSE_POSITIVE: [['REOPENED', 'tr.reopen']],
};
