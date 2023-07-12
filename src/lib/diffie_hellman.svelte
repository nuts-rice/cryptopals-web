<script lang="ts">
  import { invoke } from "@tauri-apps/api/tauri";
  let prime = 0;
  let generator = 0;
  let dhMsg = "";
  async function Generate_diffie_hellman() {
    dhMsg = await invoke("generate_dh", { prime, generator });
  }
</script>

<div>
  <form class="row" on:submit|preventDefault={Generate_diffie_hellman}>
    <input
      id="dh-prime-input"
      placeholder="Enter a prime..."
      bind:value={prime}
    />
    <input
      id="dh-gen-input"
      placeholder="Enter a generator..."
      bind:value={generator}
    />
    <button type="submit">Diffie Hellman</button>
  </form>
  <p>{dhMsg}</p>
</div>
