import express from 'express'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 5000

app.use(express.json())

// app.get('/health', (_req: express.Request, res: express.Response) => {
//   res.json({ status: 'ok', timestamp: new Date().toISOString() })
// })

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})

export default app