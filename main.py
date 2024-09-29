# https://github.com/ulif/pgp-milter/blob/master/src/pgp_milter/pgp.py
import config
import pgp
import Milter
import email

class PGPMilter(Milter.Base):
  def __init__(self):
    self.recipients = []
    self.headers = []
    self.content = bytes()

  @Milter.noreply
  def connect(_self, _ip_name, _family, _hostaddr):
    return Milter.CONTINUE

  @Milter.noreply
  def envfrom(self, name, *esmtp_params):
    self.__init__()
    # TODO: based on name determine if mail is outgoing and ignore
    return Milter.CONTINUE

  @Milter.noreply
  def envrcpt(self, name, *strings):
    self.recipients.append(name)
    return Milter.CONTINUE

  @Milter.noreply
  def header(self, k: str, v: str):
    self.headers.append((k.encode(), v.encode()))
    return Milter.CONTINUE

  def eoh(self):
    return Milter.CONTINUE

  def body(self, chunk):
    self.content += chunk
    return Milter.CONTINUE

  def eom(self):
    raw_headers = b"\n".join(map(lambda header : b"%s: %s" % header, self.headers))
    msg = email.message_from_bytes(raw_headers + b"\n\n" + self.content, policy=email.policy.default)

    if pgp.already_encrypted(msg):
      return Milter.ACCEPT
    enc_msg, encrypted = pgp.encrypt(msg, self.recipients)
    if not encrypted:
      return Milter.ACCEPT

    for (k, v) in enc_msg.items():
      self.set_header(msg, k, v)

    enc_bytes = enc_msg.as_bytes()
    enc_body = enc_bytes[enc_bytes.find(b"\n\n")+2:]
    self.replacebody(enc_body)

    return Milter.ACCEPT

  def close(self):
    self.__init__()
    return Milter.CONTINUE

  def set_header(self, old_msg, k, v):
    if k in old_msg.keys():
      for i in range(len(old_msg.get_all(k))-1, -1, -1):
        self.chgheader(k, i, '')
    self.addheader(k, v)

def main():
  Milter.factory = PGPMilter
  Milter.set_flags(Milter.ADDHDRS + Milter.CHGHDRS + Milter.CHGBODY)
  Milter.runmilter("gt-pgp-milter", config.socket)

if __name__ == '__main__':
  main()
