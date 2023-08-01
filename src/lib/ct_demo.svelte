<script lang="ts">
  import { invoke } from "@tauri-apps/api/tauri";

  let target = 0;
  let targetBools = [
    { id: 1, text: "true" , value: true},
    { id: 2, text: "false" , value: false },
  ];
  let selected : boolean = true;
  let benches = 0;

  async function Ct_demo() {
    benches = await invoke("ct_timing_demo");
  }
</script>

<div>
  <form class="row" on:submit|preventDefault={Ct_demo}>
    <select bind:value={selected} on:change={() => (benches = 0)}>
      {#each targetBools as bool}
        <option value={bool.value}>
          {bool.text}
        </option>{/each}
    </select>
    <button disabled={!benches} type="submit"> Calculate </button>
  </form>
  <p>Benchmarks for {selected ? 'true' : 'false'} are {benches} ms</p>
</div>
