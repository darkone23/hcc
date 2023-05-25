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
    '../clubhouse-server/templates/**/*.j2',
    '../clubhouse-server/src/**/*.rs'
  ],
}
