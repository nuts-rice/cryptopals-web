<script lang="ts">
  import { invoke } from "@tauri-apps/api/tauri";

  let prime = 0;
  let generator = 2;
  let k = 3;
  let userEmail = "";
  let userPass = "";
  let clientProof = "";
  async function Srp_demo() {
    clientProof = await invoke("srp_repl_demo", { prime, userEmail, userPass });
  }
</script>

<div>
  <form class="row" on:submit|preventDefault={Srp_demo}>
    <input
      id="srp-prime-input"
      placeholder="Enter a prime.."
      bind:value={prime}
    />
    <input
      id="srp-email-input"
      placeholder="Enter email..."
      bind:value={userEmail}
    />
    <input
      id="srp-pass-input"
      placeholder="Enter password..."
      bind:value={userPass}
    />
    <button type="submit"> SRP </button>
  </form>
  <p>{clientProof}</p>
</div>
