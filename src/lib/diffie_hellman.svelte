<script lang="ts">
  import { invoke } from "@tauri-apps/api/tauri";

  let prime = 0;
  let generator = 0;
  let dhMsg = "";
  let evilPrime = 0;
  let evilGenerator = 0;
  let evilMsg = "";
  async function Generate_diffie_hellman() {
    dhMsg = await invoke("generate_dh", { prime, generator });
  }
  async function Mitm_dh_demo() {
    evilMsg = await invoke("dh_mitm_attack_demo");
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

<div>
  <h1>Evil mode?</h1>
  <form class="row" on:submit|preventDefault={Mitm_dh_demo}>
    <input
      id="dh-prime-input"
      placeholder="Enter a prime..."
      bind:value={evilPrime}
    />
    <input
      id="dh-gen-input"
      placeholder="Enter a generator..."
      bind:value={evilGenerator}
    />
    <button type="submit">Evil!!! Diffie Hellman</button>
  </form>
</div>
