{
  recidive: {
    cmd: [
      // Equivalent to `sh -c echo <ip>` but preventing any code injection
      'python',
      '-c',
      |||
        import sys
        open("./out", "a+").write(sys.argv[1] + "\n")
      |||,
      '<ip>',
    ],
  },
}
