const tailwindcss = require("tailwindcss");

module.exports = { 
  plugins: [
    ["postcss-import"],
    [
      "@csstools/postcss-cascade-layers",
      {
				// Options
      }      
    ]
    ["postcss-preset-env", {
      importFrom: "css/app.css"
    }],
    tailwindcss
  ]
};
