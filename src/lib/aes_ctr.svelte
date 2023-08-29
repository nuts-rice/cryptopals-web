<script lang="ts">
  import { invoke } from "@tauri-apps/api/tauri";
  let result = "";
  async function AES_ctr_demo() {
    result = await invoke("aes_ctr_demo");
  }

</script> 

<div>
  <button type = "submit"> AES CTR edit attack </button>
  <p> {result} </p>
</div>
