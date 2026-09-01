function isEmailValidWithReason(value: string) {
  const localPartChars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%*/?|^{}`~";
  const domainChars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.';
  const blackListedLocalCharactersString = '(),:;<>@[] ';
}
