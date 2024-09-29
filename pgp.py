import key_loader
import pgpy
import email
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from copy import deepcopy

keep_headers = []
strip_headers = ["mime-version", "content-transfer-encoding"]

def encrypt(mime_msg: EmailMessage, recipients: list[str]):
  payload = extract_body(deepcopy(mime_msg))

  rcpt_keys = load_keys(recipients)
  if len(rcpt_keys) < 1:
    return mime_msg, False

  enc_msg = pgpy.PGPMessage.new(payload.as_string())
  for key in rcpt_keys:
    enc_msg = key.encrypt(enc_msg)

  container = MIMEMultipart(
    "encrypted",
    protocol="application/pgp-encrypted"
  )
  container.preamble = "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)"

  part1 = MIMEApplication(
    _data="Version: 1\n",
    _subtype="pgp-encrypted",
    _encoder=email.encoders.encode_7or8bit
  )
  part1["Content-Description"] = "PGP/MIME version identification"

  part2 = MIMEApplication(
    _data=str(enc_msg),
    _subtype="octet-stream; name=\"encrypted.asc\"",
    _encoder=email.encoders.encode_7or8bit
  )
  part2["Content-Description"] = "OpenPGP encrypted message"
  part2["Content-Disposition"] = "inline; filename=\"encrypted.asc\""

  strip_extraneous_headers(part1)
  strip_extraneous_headers(part2)
  container.attach(part1)
  container.attach(part2)
  strip_extraneous_headers(container)
  return container, True

def already_encrypted(mime_msg: EmailMessage) -> bool:
  if mime_msg.get_content_type() in ["multipart/encrypted", "application/pgp-encrypted"]:
    return True
  for part in mime_msg.iter_parts():
    if already_encrypted(part):
      return True
  return False

def extract_body(msg: EmailMessage) -> EmailMessage:
  for header in msg.keys():
      del msg[header]
  return msg

def strip_extraneous_headers(msg: EmailMessage) -> None:
  for header in msg.keys():
    if header.lower() in strip_headers:
      del msg[header]

def load_keys(recipients: list[str]) -> list[pgpy.PGPKey]:
  addrs = []
  for recipient in recipients:
    _display_name, addr = email.utils.parseaddr(recipient)
    addrs.append(addr)
  return key_loader.load_keys(addrs)
