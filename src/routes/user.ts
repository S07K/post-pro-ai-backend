import express, { Request } from "express";
import User from "../models/user";
import { authMiddleware } from "../middleware/auth";
import bcrypt from "bcryptjs";
const jwt = require("jsonwebtoken");
const SALT_ROUNDS = 10;
const JWT_TOKEN_SECRET = process.env.JWT_TOKEN_SECRET;

const app = express.Router();
app.use(express.json());

// login user route
const generateToken = (user: any) => {
  try {
    return jwt.sign(
      { id: user._id.toString(), email: user.email },
      JWT_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
  } catch (error) {
    console.error("Error in generating token", error);
  }
};
app.post("/login", (req: Request, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .send({ status: "error", message: "Missing required fields" });
  } else {
    User.findOne({ email })
      .then(async (user) => {
        // passwords are stored as bcrypt hashes, so compare instead of querying by password
        const isValid = user ? await bcrypt.compare(password, user.password) : false;
        if (user && isValid) {
          const token = await generateToken(user);
          if (token) {
            res.status(200).json({
              status: "success",
              message: "User logged in successfully",
              token: token || null,
            });
          } else {
            res.send({ status: "error", message: "Can't login user at the moment" });
          }
        } else {
          res.send({ status: "error", message: "Invalid credentials" });
        }
      })
      .catch((err) => {
        res.status(500).send({ status: "error", message: err.message });
      });
  }
});

app.post("/create", (req: Request, res) => {
    console.log(req.body);
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(400)
      .send({ status: "error", message: "Missing required fields" });
  } else {
    User.find({ email })
      .then(async (user) => {
        if (user.length > 0) {
          res.send({ status: "error", message: "User already exists" });
        } else {
          const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
          User.create({ email, password: hashedPassword })
            .then((user) => {
              res.send({
                status: "success",
                message: "User created successfully",
                data: { email: user.email },
              });
            })
            .catch((err) => {
              res.status(500).send({ status: "error", message: err.message });
            });
        }
      })
      .catch((err) => {
        res.status(500).send({ status: "error", message: err.message });
      });
  }
});

app.get("/", authMiddleware, (req: any, res) => {
  const { id } = req.user;
  if (!id) {
    return res.status(400).send({ status: "error", message: "Missing ID" });
  } else {
    User.findById(id)
      .then((user) => {
        if (user) {
          res.send({
            status: "success",
            user: { username: user.username, email: user.email, profilePic: user.profilePic, bio: user.bio, followers: user.followers, following: user.following, verified: user.verified, createdAt: user.createdAt },
          });
        } else {
          res.send({ status: "error", message: "User not found" });
        }
      })
      .catch((err) => {
        res.status(500).send({ status: "error", message: err.message });
      });
  }
});

app.get("/:id", (req: Request, res) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).send({ status: "error", message: "Missing ID" });
  } else {
    User.findById(id)
      .then((user) => {
        if (user) {
          res.send({
            status: "success",
            message: "User created successfully",
            data: { username: user.username, email: user.email },
          });
        } else {
          res.send({ status: "error", message: "User not found" });
        }
      })
      .catch((err) => {
        res.status(500).send({ status: "error", message: err.message });
      });
  }
});

app.put("/:id", async (req, res) => {
  const { id } = req.params;
  const {
    username,
    email,
    password,
    profilePic,
    bio,
    followers,
    following,
    verified,
    createdAt,
  } = req.body;
  if (!username || !email) {
    res.send({ status: "error", message: "Please provide details to update" });
  } else {
    User.findByIdAndUpdate(
      id,
      {
        username,
        email,
        password: password ? await bcrypt.hash(password, SALT_ROUNDS) : undefined,
        profilePic,
        bio,
        followers,
        following,
        verified,
        createdAt,
      },
      { new: true }
    )
      .then((user) => {
        res.send({ status: "success", user });
      })
      .catch((err) => {
        res.send(err);
      });
  }
});

app.delete("/:id", (req: Request, res) => {
  const { id } = req.params;
  User.findByIdAndDelete(id)
    .then(() => {
      res.send({ status: "success", message: "User deleted successfully" });
    })
    .catch((err) => {
      res.send(err);
    });
});

export default app;
