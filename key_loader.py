import config
import mysql.connector as mysql
import pgpy.PGPKey as pgpkey

def load_keys(addrs: list[str]) -> list[pgpkey]:
  if len(addrs) < 1:
    return []
  try:
    db = mysql.connect(**config.db_config)
    
    stmt = db.cursor()
    query = "SELECT gtid, encrypt FROM gtglobal_emails WHERE addr IN (%s) AND active = 1 AND deleted = 0" \
             % ", ".join(["%s"] * len(addrs))
    stmt.execute(query, tuple(addrs))

    encrypt_message = False
    gtids = []
    for (gtid, encrypt) in stmt:
      if encrypt:
        encrypt_message = True
      gtids.append(gtid)
    if not encrypt_message:
      return []

    query = "SELECT fingerprint, keydata FROM gtglobal_keys WHERE gtid IN (%s) AND active = 1" \
              % ", ".join(["%s"] * len(gtids))
    stmt.execute(query, tuple(gtids))
    
    keys = {}
    for (keyfpr, keydata) in stmt:
      key = pgpkey()
      try:
        key.parse(keydata)
      except:
        continue
      if keyfpr not in keys and not key.is_expired:
        keys[keyfpr] = key
    return list(keys.values())
  finally:
    try:
      stmt.close()
    except:
      pass
    try:
      db.close()
    except:
      pass
