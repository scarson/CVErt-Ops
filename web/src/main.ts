// ABOUTME: Application entry point — initializes Vue, Pinia, and Router.
// ABOUTME: Mounts the app to the DOM.

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { setPasswordChangeRequiredHandler } from './lib/api/client'
import { useAuthStore } from './stores/auth'
import './assets/main.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)

// A session flagged for a password change mid-session gets 403 on every other
// request; reload the user so the router guard sends them to the account page.
setPasswordChangeRequiredHandler(async () => {
  const auth = useAuthStore()
  await auth.fetchMe()
  router.push({ name: 'account' })
})
app.config.errorHandler = (err, instance, info) => {
  console.error('Unhandled error:', err, info)
}

app.mount('#app')
