<script lang="ts">
  import Generate_diffie_hellman from "./lib/diffie_hellman.svelte";
  import Srp_repl_demo from "./lib/srp.svelte";
  import Ct_demo from "./lib/ct_demo.svelte";
  import AES_ctr_demo from "./lib/aes_ctr.svelte";
</script>

<main class="container">
  <div class="row">
    <Generate_diffie_hellman />
  </div>
  <div class="row">
    <Srp_repl_demo />
  </div>
  <div class="row">
    <Ct_demo />
  </div>
  <div class="row"> 
  <AES_ctr_demo/>
  </div>
</main>

<style>
</style>
