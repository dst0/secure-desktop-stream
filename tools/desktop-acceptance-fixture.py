#!/usr/bin/env python3
"""Fullscreen synthetic desktop for streaming/input/clipboard acceptance; records hashes only."""

import argparse
import hashlib
import json
import os
import stat
import struct
import time
import zlib
from pathlib import Path

import gi

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--gtk", choices=("3.0", "4.0"), required=True)
parser.add_argument("--state-dir", type=Path, required=True)
parser.add_argument("--host-label", required=True)
parser.add_argument("--self-test", action="store_true", help="Exercise widgets in an isolated test display")
args = parser.parse_args()
if args.self_test and os.environ.get("GDK_BACKEND") != "x11":
    raise SystemExit("Isolated self-test requires explicit GDK_BACKEND=x11 with xvfb-run")
gi.require_version("Gtk", args.gtk)
gi.require_version("Gdk", args.gtk)
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, Gio, GLib, Gtk

args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
directory = args.state_dir.lstat()
if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or directory.st_mode & 0o077:
    raise SystemExit("Fixture state directory must be private and owned by this user")

TEXT = "SDS-CLIPBOARD-20261121-synthetic"
INPUT = "SDS-INPUT-20261121"
MAX_IMAGE_DIM = 4096
MAX_IMAGE_PIXELS = 4096 * 4096
state = {"host": args.host_label, "clicks": 0, "mapped": False}


def publish(**values):
    state.update(values)
    temporary = args.state_dir / "state.json.new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(state, file, sort_keys=True)
        file.write("\n")
    os.replace(temporary, args.state_dir / "state.json")


def image_metadata(pixbuf):
    width, height = pixbuf.get_width(), pixbuf.get_height()
    pixels, stride, channels = pixbuf.get_pixels(), pixbuf.get_rowstride(), pixbuf.get_n_channels()
    if (width <= 0 or height <= 0 or width > MAX_IMAGE_DIM or height > MAX_IMAGE_DIM or
            width * height > MAX_IMAGE_PIXELS or channels < 3 or stride < width * channels or
            len(pixels) < (height - 1) * stride + width * channels):
        publish(clipboard_error="image_dimensions_rejected",
                clipboard_image_width=width, clipboard_image_height=height)
        return
    digest = hashlib.sha256()
    for y in range(height):
        for x in range(width):
            offset = y * stride + x * channels
            digest.update(pixels[offset:offset + 3])
    publish(clipboard_image_width=width, clipboard_image_height=height,
            clipboard_image_rgb_sha256=digest.hexdigest())


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


png = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 32, 32, 8, 2, 0, 0, 0))
png += png_chunk(b"IDAT", zlib.compress((b"\0" + bytes((32, 120, 220)) * 32) * 32)) + png_chunk(b"IEND", b"")
image_path = args.state_dir / "synthetic-blue.png"
fd = os.open(image_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "wb") as file:
    file.write(png)


class Fixture(Gtk.Application):
    def do_activate(self):
        display = Gdk.Display.get_default()
        if args.self_test and not display.get_name().startswith(":"):
            raise RuntimeError("Self-test refused a display outside Xvfb")
        publish(display_name=display.get_name())
        self.window = Gtk.ApplicationWindow(application=self)
        self.window.set_title("SDS acceptance — " + args.host_label)
        self.window.set_default_size(1280, 720)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        for edge in ("top", "bottom", "start", "end"):
            getattr(box, "set_margin_" + edge)(36)
        attach = box.append if args.gtk == "4.0" else lambda widget: box.pack_start(widget, False, False, 0)
        title = Gtk.Label(label="Secure Desktop Stream — " + args.host_label)
        attach(title)
        attach(Gtk.Label(label="Synthetic acceptance fixture. No personal data is displayed."))
        attach(Gtk.Label(label="Type SDS-INPUT-20261121 into the field through Moonlight."))
        entry = Gtk.Entry()
        entry.connect("changed", lambda widget: publish(input_matches=widget.get_text() == INPUT,
                      input_length=len(widget.get_text()),
                      input_sha256=hashlib.sha256(widget.get_text().encode()).hexdigest()))
        attach(entry)
        counter = Gtk.Button(label="Click counter: 0")

        def clicked(button):
            state["clicks"] += 1
            button.set_label("Click counter: " + str(state["clicks"]))
            publish()

        counter.connect("clicked", clicked)
        attach(counter)
        self.clipboard = Gdk.Display.get_default().get_clipboard() if args.gtk == "4.0" else Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)

        def copy_text(_):
            if args.gtk == "4.0":
                self.clipboard.set_content(Gdk.ContentProvider.new_for_bytes(
                    "text/plain;charset=utf-8", GLib.Bytes.new(TEXT.encode())))
            else: self.clipboard.set_text(TEXT, -1)
            publish(clipboard_action="copied_synthetic_text")

        def text_result(value):
            publish(clipboard_text_matches=value == TEXT, clipboard_text_length=len(value or ""))

        def paste_text(_):
            if args.gtk == "4.0":
                def done(clipboard, result):
                    try: text_result(clipboard.read_text_finish(result))
                    except GLib.Error as error:
                        publish(clipboard_error="text_unavailable", clipboard_error_domain=error.domain,
                                clipboard_error_code=error.code)
                self.clipboard.read_text_async(None, done)
            else: text_result(self.clipboard.wait_for_text())

        def copy_image(_):
            if args.gtk == "4.0":
                self.clipboard.set_content(Gdk.ContentProvider.new_for_bytes("image/png", GLib.Bytes.new(png)))
            else: self.clipboard.set_image(GdkPixbuf.Pixbuf.new_from_file(str(image_path)))
            publish(clipboard_action="copied_synthetic_png")

        def paste_image(_):
            if args.gtk == "4.0":
                def done(clipboard, result):
                    try:
                        texture = clipboard.read_texture_finish(result)
                        tw, th = texture.get_width(), texture.get_height()
                        if tw <= 0 or th <= 0 or tw > MAX_IMAGE_DIM or th > MAX_IMAGE_DIM or tw * th > MAX_IMAGE_PIXELS:
                            publish(clipboard_error="image_dimensions_rejected",
                                    clipboard_image_width=tw, clipboard_image_height=th)
                            return
                        loader = GdkPixbuf.PixbufLoader.new_with_type("png")
                        loader.write(texture.save_to_png_bytes().get_data())
                        loader.close()
                        image_metadata(loader.get_pixbuf())
                    except (GLib.Error, AttributeError): publish(clipboard_error="image_unavailable")
                self.clipboard.read_texture_async(None, done)
            else:
                image = self.clipboard.wait_for_image()
                if image is None: publish(clipboard_error="image_unavailable")
                else: image_metadata(image)

        for label, callback in (("Copy synthetic text", copy_text), ("Check pasted text", paste_text),
                                ("Copy synthetic PNG", copy_image), ("Check pasted PNG", paste_image)):
            button = Gtk.Button(label=label)
            button.connect("clicked", callback)
            attach(button)
        if args.gtk == "4.0": self.window.set_child(box)
        else: self.window.add(box)
        self.window.connect("map", lambda _: publish(mapped=True))
        self.window.fullscreen()
        if args.gtk == "4.0": self.window.present()
        else: self.window.show_all()
        if args.self_test:
            deadline = time.monotonic() + 10
            step = 0

            def exercise():
                nonlocal step
                if time.monotonic() > deadline:
                    publish(self_test_passed=False)
                    self.quit()
                    return False
                if step == 0:
                    entry.set_text(INPUT)
                    clicked(counter)
                    copy_text(None)
                    step = 1
                elif step == 1:
                    paste_text(None)
                    step = 2
                elif step == 2 and state.get("clipboard_text_matches"):
                    copy_image(None)
                    step = 3
                elif step == 3:
                    paste_image(None)
                    step = 4
                elif step == 4 and "clipboard_image_rgb_sha256" in state:
                    expected = hashlib.sha256(bytes((32, 120, 220)) * 32 * 32).hexdigest()
                    publish(self_test_passed=state.get("input_matches") and state["clicks"] == 1 and
                            state["clipboard_image_rgb_sha256"] == expected)
                    self.quit()
                    return False
                return True

            GLib.timeout_add(150, exercise)


Fixture(application_id="local.secure-desktop-stream.AcceptanceFixture", flags=Gio.ApplicationFlags.NON_UNIQUE).run([])
