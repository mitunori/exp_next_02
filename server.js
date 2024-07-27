const express = require("express");

const app = express();

const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv");
const PORT = 8888;

const prisma = new PrismaClient();

app.use(express.json());

// 新規ユーザーAPI
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;

  // 暗号化対応=bcryptを使ってハッシュ化する🤗
  const hasedPass = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      username,
      email,
      password: hasedPass,
    },
  });

  return res.json({ user });
});

// ログインAPI
app.post("/api/auth/login", async (req, res) => {
  // email, passwordをチェックするために取得します🤗
  const { email, password } = req.body;

  // whereはSQL等で出てくる条件を絞るという条件です🤗
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return res.status(401).json({
      error: "そのユーザーは存在しません",
    });
  }

  //compare bcryptのcompareは比較をしてチェックするおまじないです🤗
  const isPasswordCheck = await bcrypt.compare(password, user.password);

  if (!isPasswordCheck) {
    return res.status(401).json({
      error: "そのパスワードは間違っていますよ！",
    });
  }

  // token = チケットのイメージです🤗
  const token = jwt.sign({ id: user.id }, process.env.KEY, {
    expiresIn: "1d",
  });

  return res.json({ token });
});

app.listen(PORT, () => console.log("server start"));
