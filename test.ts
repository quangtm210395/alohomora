
export class Enforcer {
  x: number;
  y: string;
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }

  enforce() {
    const x = this.x;
    const y = this.y;
    return function(a: number, b: string) {
      console.log('a, b: ', a, b);
      console.log('x: ', x);
      console.log('y: ', y);
    };
  }
}

function enforce() {
  return new Enforcer(1, '2').enforce().apply(null, [3, '4']);
}

enforce();
