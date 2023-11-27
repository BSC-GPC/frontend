<template>
  <b-modal id="projectConfirmDeleteModal" size="md" hide-header-close no-stacking :title="$t('message.confirm_delete')">
    <p>Are you sure you want to delete this project? This action cannot be undone.</p>
    <template v-slot:modal-footer="{ cancel }">
      <b-button size="md" variant="secondary" @click="cancel()">{{ $t('message.cancel') }}</b-button>
      <b-button size="md" variant="outline-danger" @click="deleteProject()">{{ $t('message.delete') }}</b-button>
    </template>
  </b-modal>
</template>
  
<script>
  export default {
    name: "ProjectConfirmDeleteModal",
    props: {
      uuid: String
    },
    methods: {
      deleteProject: function() {
        this.$root.$emit('bv::hide::modal', 'projectConfirmDeleteModal');
        let url = `${this.$api.BASE_URL}/${this.$api.URL_PROJECT}/` + this.uuid;
        this.axios.delete(url).then((response) => {
          this.$toastr.s(this.$t('message.project_deleted'));
          this.$router.replace({ name: "Projects" });
        }).catch((error) => {
          this.$toastr.w(this.$t('condition.unsuccessful_action'));
        });
      }
    }
  }
</script>
  
<style lang="scss" scoped>
  @import "../../../assets/scss/vendors/vue-tags-input/vue-tags-input";
  .custom-control {
    padding-bottom: 0.3rem;
  }
</style>
  