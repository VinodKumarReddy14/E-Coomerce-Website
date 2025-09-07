import { Redis } from "ioredis";

const client = new Redis(process.env.UPSTASH_REDIS_URI);

client.set("foo", "bar");
