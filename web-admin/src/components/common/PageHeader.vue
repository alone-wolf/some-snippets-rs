<template>
  <div class="page-header">
    <div class="page-header__copy">
      <div v-if="eyebrow" class="page-header__eyebrow">{{ eyebrow }}</div>
      <h2>{{ title }}</h2>
      <p v-if="description">{{ description }}</p>
    </div>
    <div v-if="$slots.default" class="page-header__actions page-actions">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  title: string;
  description?: string;
  eyebrow?: string;
}>();
</script>

<style scoped lang="scss">
.page-header {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 16px;
  padding: 16px 18px;
  border: 1px solid rgba(58, 47, 35, 0.12);
  border-radius: 18px;
  background:
    radial-gradient(circle at top left, rgba(205, 153, 78, 0.22), transparent 34%),
    linear-gradient(135deg, rgba(255, 252, 246, 0.96), rgba(246, 238, 226, 0.94));
  box-shadow: 0 12px 28px rgba(78, 62, 43, 0.08);

  &__copy {
    max-width: 760px;
  }

  &__eyebrow {
    display: inline-flex;
    margin-bottom: 8px;
    padding: 4px 8px;
    border-radius: 999px;
    background: rgba(98, 73, 31, 0.08);
    color: #6a522b;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  h2 {
    margin: 0;
    color: #261b12;
    font-size: 24px;
    line-height: 1.1;
  }

  p {
    margin: 8px 0 0;
    color: #6c6156;
    font-size: 13px;
    line-height: 1.5;
  }

  &__actions {
    justify-content: flex-end;
  }

  @media (max-width: 960px) {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
