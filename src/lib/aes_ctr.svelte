<script lang="ts">
  import { invoke } from "@tauri-apps/api/tauri";
  let result = "";
  async function AES_ctr_demo() {
    result = await invoke("aes_ctr_demo");
  }

</script> 

<div>
  <button on:click={AES_ctr_demo}> Edit AES CTR ciphertext </button>
  <p> {result} </p>
</div>
