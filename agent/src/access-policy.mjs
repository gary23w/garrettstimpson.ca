export function accessPasswordMinimum(env = {}) {
  const configured = Number(env.ACCESS_PASSWORD_MIN_LENGTH);
  return Number.isInteger(configured) && configured >= 8 && configured <= 128 ? configured : 16;
}
