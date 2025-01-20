function input(message) {
  return new Promise((resolve) => {
    process.stdout.write(message);
    process.stdin.once("data", (data) => {
      resolve(data.toString().trim());
    });
  });
}

async function main() {
  const args = process.argv;
  console.log(`Process ID: ${process.pid}`);

  const buffer = new ArrayBuffer(4);
  let numView = new Uint32Array(buffer);

  if (args.length != 3) {
    console.log("usage: script.js <number>");
    return;
  }

  numView[0] = parseInt(args[2]);

  while (true) {
    console.log(`Number is ${numView[0]}`);
    const strNumber = await input("Enter a new number: ");
    numView[0] = parseInt(strNumber);
  }
}

main();
