# web-admin

`web-admin` 是当前项目的后台型 SPA 子项目。

## 技术栈

- Vue 3
- TypeScript
- Vite
- Pinia
- Vue Router
- Element Plus

## 本地开发

安装依赖：

```bash
npm install
```

启动前端开发服务器：

```bash
npm run dev
```

默认会把以下前缀代理到本地 `axum` 服务：

- `/healthz`
- `/collections`
- `/contents`
- `/nodes`
- `/node-lineages`
- `/draft`
- `/latest`
- `/versions`
- `/files`

## 构建

```bash
npm run build
```

构建输出目录为：

```text
web-admin/dist
```

## 质量检查

```bash
npm run lint
npm run test
```
