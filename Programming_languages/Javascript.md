# JS Tricks

## Function code to string

- In JavaScript, you can get function body by casting it to a string:

```javascript
function a() {}
console.log(a+'')
// "function a() {}"
```



## Strict mode


### no-strict mode

#### arguments.callee

- In non-strict mode, arguments.callee returns it self for IIFE(Immediately Invoked Function Expression).
- However, 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode

```javascript
(function(){ return arguments.callee+''; /* flag */})()
"(function(){ return arguments.callee+''; /* flag */})()"
```