//Based on https://github.com/mprimi/portable-secret

const blockSize = 16 // bytes (for AES, IV)
const saltSize = 16 // bytes (for PBKDF2)
const iterations = 1000000 // key derivation (with PBKDF2)
const keySize = 32 // bytes (derived with PBKDF2, used by AES)

//From https://stackoverflow.com/questions/34309988/byte-array-to-hex-string-conversion-in-javascript
Object.prototype.toHexString =function() {
    return Array.from(this, function(byte) {
             return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

Object.prototype.toByteArray = function (){
    const a = this.match(/.{2}/g).map(i=>parseInt(i,16));
   return Uint8Array.from(a);
}

class PCrypt {
    #iv;
    #salt;
    #passwordkey;
    #file;
    #cipher;

    //parameters takes in hex-string
    constructor(iv=false,salt=false,cipher=false) {
        this.#iv = iv?iv.toByteArray():crypto.getRandomValues(new Uint8Array(blockSize));
        this.#salt = salt?salt.toByteArray():crypto.getRandomValues(new Uint8Array(saltSize));
        this.#cipher = cipher?cipher.toByteArray():0;
      }

    //Uint8Array automatically padded
    //https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    set file(file){
        const cache = Array.from(file);
        const paddamt = blockSize - (file.length % blockSize);
        const padd = new Array(paddamt).fill(paddamt);      
        this.#file = Uint8Array.from(cache.concat(padd));
    } 
    
    get file(){
        return this.#file;
    }

    get salt() {
       return this.#salt;
    }

    get iv() {
        return this.#iv;
     }

    get cipher() {
        return this.#cipher;
    }

    async setPasswordToDKey(password,decrypting=false){
        const usefor = decrypting?"decrypt":"encrypt";
        try{
             const temp = await crypto.subtle.importKey("raw",new TextEncoder().encode(password),{name: "PBKDF2"}, false, ["deriveKey"]);
             this.#passwordkey = await crypto.subtle.deriveKey({name: "PBKDF2",salt: this.#salt,iterations: iterations,hash: "SHA-1"},temp,{name: "AES-GCM",length: keySize * 8},false,[usefor]);
            return true;
        }catch(e){
            console.log(e);
            return false
        }
    }

    async encrypt(){
        try{
          const cipherBuffer = await crypto.subtle.encrypt({name: "AES-GCM",iv: this.#iv,},this.#passwordkey,this.#file);
          this.#cipher = new Uint8Array(cipherBuffer);
            return true;
        }catch(e){
            console.log(e);
            return false
        }
    }

    async decrypt(){
        try{
         const decryptedBuffer = await crypto.subtle.decrypt({name: "AES-GCM",iv: this.#iv, },this.#passwordkey, this.#cipher);
         const file = new Uint8Array(decryptedBuffer);
         this.#file = file.slice(0, file.length - file[file.length-1]);
         return true;
        }catch(e){
            console.log(e);
            return false;
        }
    }

     refreshIV(){
        this.#iv = crypto.getRandomValues(new Uint8Array(blockSize));
     }

     refreshSalt(){
        this.#salt = crypto.getRandomValues(new Uint8Array(saltSize));
     }

}

export {PCrypt};

