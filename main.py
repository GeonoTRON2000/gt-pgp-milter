# https://github.com/ulif/pgp-milter/blob/master/src/pgp_milter/pgp.py
import config
import pgp
import Milter
import email
from io import BytesIO

class PGPMilter(Milter.Base):
  def __init__(self):
    self.recipients = []
    self.headers = []
    self.fp = None

  @Milter.noreply
  def connect(_self, _ip_name, _family, _hostaddr):
    return Milter.CONTINUE

  @Milter.noreply
  def envfrom(self, name, *esmtp_params):
    if self.fp:
      self.fp.close()

    self.fp = BytesIO()
    self.recipients = []
    self.headers = []
    return Milter.CONTINUE

  @Milter.noreply
  def envrcpt(self, name, *strings):
    self.recipients.append(name)
    return Milter.CONTINUE

  @Milter.noreply
  def header(self, k, v):
    self.headers.append((k, v))
    self.fp.write(("%s: %s\n" % (k, v)).encode())
    return Milter.CONTINUE

  #@Milter.noreply
  def eoh(self):
    self.fp.write(b"\n")
    return Milter.CONTINUE

  #@Milter.noreply
  def body(self, chunk):
    self.fp.write(chunk)
    return Milter.CONTINUE

  def eom(self):
    self.fp.seek(0)
    msg = email.message_from_binary_file(self.fp, policy=email.policy.default)

    if pgp.already_encrypted(msg):
      return Milter.ACCEPT
    enc_msg, encrypted = pgp.encrypt(msg, self.recipients)
    if not encrypted:
      return Milter.ACCEPT

    self.replace_headers(msg, enc_msg)
    # TODO: this is sketch
    enc_bytes = enc_msg.as_bytes()
    enc_body = enc_bytes[enc_bytes.find(b"\n\n")+2:]
    self.replacebody(enc_body)

    return Milter.ACCEPT
    
  def close(self):
    self.recipients = []
    self.headers = []
    self.fp.close()
    return Milter.CONTINUE

  def replace_headers(self, msg, enc_msg):
    for (k, v) in msg.items():
      for i in range(len(msg.get_all(k))-1, -1, -1):
        self.chgheader(k, i, '')
    for (k, v) in enc_msg.items():
      self.addheader(k, v)

def main():
  Milter.factory = PGPMilter
  Milter.set_flags(Milter.ADDHDRS + Milter.CHGHDRS + Milter.CHGBODY)
  Milter.runmilter("gt-pgp-milter", config.socket)

if __name__ == '__main__':
  main()
