# LightDSU Security Review (v1 hardening)

## Scope

Review-ul a acoperit:
- integritatea ancorei (`ssi:event`, chain, semnături)
- controlul accesului (grant/revoke/check)
- consistența operațiilor FS
- reziliența la concurență pe commit
- ergonomia de embed pentru identitate actor (`currentDID`)

## Decizii aplicate

1. **Scope enforcement pentru ADMIN**
   - `ADMIN` nu mai bypassează scope-ul grantului.
   - Verificarea este: *scope match* -> *permission bits*.

2. **Grant identity corectă**
   - `grantId` este unic per grant (`eventHash` al GRANT-ului).
   - `REVOKE` cu `grantId` țintește grantul exact.
   - `REVOKE` fără `grantId` revocă toate granturile active care corespund tuplei `(subjectHash, resourceHash, permissions)`.

3. **Prevenire privilege bypass la revoke by grantId**
   - Dacă `grantId` este prezent, autorizarea se face pe scope-ul grantului țintă, nu pe scope-ul furnizat de apelant.

4. **Validări mai stricte pe FS**
   - `readDir/listFiles/listFolders` eșuează pe path inexistent sau non-folder.
   - `delete` eșuează pe path inexistent.
   - `rename` blochează overwrite implicit și mutare în propriul subtree.

5. **`appendToFile` fără silent fallback pe erori critice**
   - Se tratează ca create-on-missing doar `ERR_INVALID_PATH`.
   - Erori de integritate/decriptare se propagă.

6. **Concurență lock robustă**
   - Locking tratează explicit doar `EEXIST` ca retry; alte erori I/O se propagă.

7. **Embedability: DID actor switch explicit**
   - `engine.setCurrentDID(did)`
   - `mountedDsu.setCurrentDID(did)`
   - sincronizează și `didStrategy` dacă suportă `setCurrentDID` / `currentDID`.

## Riscuri rămase (cunoscute)

1. **DefaultDidStrategy este doar strategie implicită locală**
   - este utilă pentru test/dev/embed local;
   - pentru producție se recomandă strategie DID externă (HSM/KMS/wallet).

2. **Append semantic**
   - `appendToFile` rămâne read+rewrite (corect funcțional, dar nu optim pentru fișiere foarte mari).
   - optimizarea incrementală pe chunks poate fi introdusă ulterior fără schimbare de API.

3. **Garbage collection policy**
   - implementarea actuală respectă modurile declarate, dar strategiile avansate (window-based pe timestamp/version metadata extins) pot fi rafinate ulterior.
