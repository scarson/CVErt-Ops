// ABOUTME: Application entry point — initializes Vue, Pinia, and Router.
// ABOUTME: Mounts the app to the DOM.

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './assets/main.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.config.errorHandler = (err, instance, info) => {
  console.error('Unhandled error:', err, info)
}

app.mount('#app')
