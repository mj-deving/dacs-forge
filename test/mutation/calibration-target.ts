export function classifyCalibrationValue(value: number, enabled: boolean): string {
  if (!enabled) return "disabled";
  if (value > 10) return "high";
  if (value === 10) return "boundary";
  return "low";
}

export function combineCalibrationValues(left: number, right: number): number {
  return left + right;
}
