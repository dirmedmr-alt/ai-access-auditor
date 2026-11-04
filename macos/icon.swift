// Draws a 1024px shield icon to the path given as argv[1]
import Cocoa
let s: CGFloat = 1024
let img = NSImage(size: NSSize(width: s, height: s))
img.lockFocus()
let bg = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185)
NSGradient(starting: NSColor(red: 0.20, green: 0.38, blue: 0.88, alpha: 1), ending: NSColor(red: 0.10, green: 0.17, blue: 0.45, alpha: 1))!.draw(in: bg, angle: -90)
let sh = NSBezierPath()
sh.move(to: NSPoint(x: 512, y: 800)); sh.line(to: NSPoint(x: 740, y: 710))
sh.curve(to: NSPoint(x: 512, y: 220), controlPoint1: NSPoint(x: 740, y: 450), controlPoint2: NSPoint(x: 640, y: 300))
sh.curve(to: NSPoint(x: 284, y: 710), controlPoint1: NSPoint(x: 384, y: 300), controlPoint2: NSPoint(x: 284, y: 450))
sh.close(); NSColor.white.setFill(); sh.fill()
let ck = NSBezierPath(); ck.lineWidth = 56; ck.lineCapStyle = .round; ck.lineJoinStyle = .round
ck.move(to: NSPoint(x: 410, y: 520)); ck.line(to: NSPoint(x: 490, y: 440)); ck.line(to: NSPoint(x: 625, y: 600))
NSColor(red: 0.16, green: 0.32, blue: 0.80, alpha: 1).setStroke(); ck.stroke()
img.unlockFocus()
let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
