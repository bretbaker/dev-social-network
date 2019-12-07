const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route    POST api/users
// @desc     register user
// @access   public
router.post(
  '/',
  // create validator logic
  [
    check('name', 'Name is required')
      .not()
      .isEmpty(),
    check('email', 'Please use a valid email address').isEmail(),
    check(
      'password',
      'Password must be at least 6 characters in length'
    ).isLength({ min: 6 })
  ],
  async (req, res) => {
    // init validator logic
    const errors = validationResult(req);
    // if error return error
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // destructure req.body
    const { name, email, password } = req.body;

    try {
      // search db by email
      let user = await User.findOne({ email: email });
      // if email already exists return error
      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User already exists' }] });
      }
      // if not proceed
      // get avatar for user or provide default img if none
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      });
      // instantiate new user
      user = new User({
        name,
        email,
        avatar,
        password
      });
      // encrypt password before saving to db
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      // save new user to db
      await user.save();
      // create payload for jwt
      const payload = {
        user: {
          id: user.id
        }
      };
      // create token
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 36000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
