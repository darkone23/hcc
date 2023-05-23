
let range = n => Array.from(Array(n).keys())

range(100).forEach(e => {
  
  let x = String(e).padStart(2, "0");
  
  console.log(".seek-left-" + e + "pc { left: calc(220px * 0." + x + "); }");
  
});