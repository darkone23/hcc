module.exports = {
  content: [],
  theme: {
    letterSpacing: {
      tighter: "-0.5rem",
      widest: "3rem"
    },
    extend: {
      
    },
  },
  plugins: [
    require('@tailwindcss/forms')({
      strategy: 'class',
    })
  ],
  content: [
    './assets/**/*.html',
    './src/**/*.rs',
    './css/**/*.css',
    '../clubhouse/templates/**/*.j2',
    '../clubhouse/src/**/*.rs'
  ],
}
