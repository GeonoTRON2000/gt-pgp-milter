import key_loader
import pgpy
import email
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from copy import deepcopy

def encrypt(mime_msg: EmailMessage, recipients: list[str]):
  rcpt_keys = load_keys(recipients)
  if len(rcpt_keys) < 1:
    return mime_msg, False

  headers = mime_msg.items()
  payload = extract_body(mime_msg)
  enc_msg = pgpy.PGPMessage.new(payload.as_string())
  for key in rcpt_keys:
    enc_msg = key.encrypt(enc_msg)

  container = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")
  part1 = MIMEApplication(
    _data="Version: 1\n",
    _subtype="pgp-encrypted",
    _encoder=email.encoders.encode_7or8bit
  )
  part2 = MIMEApplication(
    _data=str(enc_msg),
    _subtype="octet-stream; name=encrypted.asc",
    _encoder=email.encoders.encode_7or8bit
  )
  container.attach(part1)
  container.attach(part2)
  container["Content-Disposition"] = "inline"
  add_headers(container, headers)
  return container, True

def already_encrypted(mime_msg: EmailMessage) -> bool:
  if mime_msg.get_content_type() in ["multipart/encrypted", "application/pgp-encrypted"]:
    return True
  for part in mime_msg.iter_parts():
    if already_encrypted(part):
      return True
  return False

def extract_body(msg: EmailMessage) -> EmailMessage:
  msg = deepcopy(msg)
  for header in msg.keys():
    if not header.lower().startswith("content-"):
      del msg[header]
  return msg

def add_headers(msg: EmailMessage, headers: list[map]) -> None:
  for (k, v) in headers:
    if k.lower().startswith("content-"):
      continue
    if k in msg.keys():
        del msg[k]
    if not isinstance(v, str):
        v = v.encode()
    msg.add_header(k, v)

def load_keys(recipients: list[str]) -> list[pgpy.PGPKey]:
  addrs = []
  for recipient in recipients:
    _display_name, addr = email.utils.parseaddr(recipient)
    addrs.append(addr)
  return key_loader.load_keys(addrs)
