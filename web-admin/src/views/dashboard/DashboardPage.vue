<template>
  <PageHeader
    eyebrow="Overview"
    title="内容控制台"
    description="把 Collection、Content、Node 的高频操作收敛到一条工作流里，减少在设置页、编辑页、版本页之间的来回切换。"
  >
    <el-button type="primary" @click="$router.push('/collections')">进入工作台</el-button>
  </PageHeader>

  <section class="dashboard-hero">
    <div class="dashboard-hero__lead">
      <span>One Workspace</span>
      <h3>围绕内容实体组织后台，而不是围绕页面组织后台。</h3>
      <p>先选 Collection，再处理 Content，最后直接进入 Node 层面的 draft 操作和版本动作。</p>
    </div>
    <div class="dashboard-hero__grid">
      <article class="dashboard-stat">
        <strong>Collection</strong>
        <p>创建、修改、选择可见性与描述。</p>
      </article>
      <article class="dashboard-stat">
        <strong>Content</strong>
        <p>在当前 collection 下创建、修改、查看版本入口。</p>
      </article>
      <article class="dashboard-stat">
        <strong>Node</strong>
        <p>直接在工作台完成新增、编辑、重排与移除。</p>
      </article>
    </div>
  </section>

  <section class="dashboard-grid">
    <el-card class="page-card dashboard-card" shadow="never">
      <template #header>工作流</template>
      <ol>
        <li>在左侧选择目标 Collection，或者新建一个 collection。</li>
        <li>在中间选择 Content，编辑标题、状态、Schema 与版本入口。</li>
        <li>在右侧直接维护 Node 列表，处理 copy-on-write 和 draft 顺序。</li>
      </ol>
    </el-card>
    <el-card class="page-card dashboard-card" shadow="never">
      <template #header>使用建议</template>
      <p>如果你的主要目标是日常录入与编排，直接进入工作台即可。版本详情页仍保留，用于查看快照内容和执行回滚。</p>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import PageHeader from "@/components/common/PageHeader.vue";
</script>

<style scoped lang="scss">
.dashboard-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr);
  gap: 12px;
  margin-bottom: 12px;

  &__lead {
    padding: 20px;
    border-radius: 20px;
    background:
      radial-gradient(circle at top left, rgba(204, 153, 87, 0.25), transparent 36%),
      linear-gradient(135deg, #fff9f1, #efe4d4);
    border: 1px solid rgba(93, 73, 45, 0.12);

    span {
      display: inline-flex;
      margin-bottom: 10px;
      padding: 4px 8px;
      border-radius: 999px;
      background: rgba(92, 69, 38, 0.08);
      color: #6a532d;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    h3 {
      margin: 0;
      color: #2b1d11;
      font-size: 26px;
      line-height: 1.2;
    }

    p {
      margin: 10px 0 0;
      color: #6c6156;
      font-size: 13px;
      line-height: 1.6;
    }
  }

  &__grid {
    display: grid;
    gap: 10px;
  }
}

.dashboard-stat {
  padding: 16px;
  border-radius: 16px;
  background: rgba(255, 252, 247, 0.82);
  border: 1px solid rgba(93, 73, 45, 0.1);
  box-shadow: 0 16px 34px rgba(80, 63, 43, 0.06);

  strong {
    display: block;
    margin-bottom: 6px;
    color: #2f2216;
    font-size: 17px;
  }

  p {
    margin: 0;
    color: #6a6056;
    font-size: 13px;
    line-height: 1.5;
  }
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.dashboard-card {
  border-radius: 16px;

  ol,
  p {
    margin: 0;
    color: #5f554a;
    font-size: 13px;
    line-height: 1.7;
  }
}

@media (max-width: 960px) {
  .dashboard-hero,
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}
</style>
