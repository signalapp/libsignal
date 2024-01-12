module.exports = {
  singleQuote: true,
  trailingComma: 'es5',
  overrides: [
    {
      files: "*.ts.in",
      options: { parser: "typescript" }
    }
  ]
};
