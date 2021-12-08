# Icedream's fancy vaccination/test certificate card tool

This is just a tool I wrote to transform my vaccine certificate QR codes into something I can carry in my wallet instead of using my phone.

Yes, I get the irony. You're supposed to use your phone because it's the thing you will carry around the most, but what if your phone goes empty or stops working? Hopefully you got your A4-sized paper with the QR code on it with you!

...Or you just make a smaller badge-sized version of the information and the QR code and print that to put inside your wallet instead. And this tool takes care of generating the content to print for it.

## Building

Just do this the same way as any simple Go project:

```bash
# simply fetch and compile with this:
go install github.com/icedream/fancy-vaccert@latest

# or if you cloned this repository and want to build from it:
go build
```

## Running

```bash
fancy-vaccert your-qr-image.png
```
