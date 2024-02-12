const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const session = require("express-session");
const flash = require("connect-flash");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { allowedNodeEnvironmentFlags } = require("process");

mongoose.connect("mongodb://127.0.0.1:27017/vacayDB");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "your-secret-key", // Replace with a secure secret key
    resave: false,
    saveUninitialized: true,
  })
);

app.set("view engine", "ejs");
app.set("views", __dirname + "/views");
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static("uploads"));
app.use(flash());

const saltRounds = 10;

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage: storage });

const vacayGuestSchema = new mongoose.Schema({
  name: String,
  email: String,
  phoneNum: Number,
  password: String,
  type: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  profilePic: {
    type: String,
    default: "uploads\\defaultPic\\guest.jpg",
  },
});

const vacayHostSchema = new mongoose.Schema({
  name: String,
  email: String,
  phoneNum: Number,
  password: String,
  bankNum: Number,
  type: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  profilePic: {
    type: String,
    default: 'uploads\\defaultPic\\host.jpg',
  },
});

const vacayAdminSchema = new mongoose.Schema({
  email: String,
  password: String,
  profilePic: {
    type: String,
    default: "",
  },
});

const propertyHostSchema = new mongoose.Schema({
  name: String,
  address: String,
  description: String,
  price: String,
  guestNum: Number,
  hostId: { type: mongoose.Schema.Types.ObjectId, ref: "VacayHost" },
  images: [
    {
      data: Buffer,
      contentType: String,
    },
  ],
});

const bookingGuestSchema = new mongoose.Schema({
  name: String,
  phoneNum: Number,
  checkin: Date,
  checkout: Date,
  guestNum: Number,
  totalPrice: Number,
  bankNo: Number,
  bankType: String,
});

const bookingHistorySchema = new mongoose.Schema({
  propertyId: { type: mongoose.Schema.Types.ObjectId, ref: "PropertyHost" },
  bookingId: { type: mongoose.Schema.Types.ObjectId, ref: "BookingGuest" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "VacayGuest" },
  timestamp: { type: Date, default: Date.now },
});

const propertyRatingSchema = new mongoose.Schema({
  propertyId: { type: mongoose.Schema.Types.ObjectId, ref: "PropertyHost" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "VacayGuest" },
  rating: { type: Number, min: 1, max: 5, required: true },
  review: String,
  timestamp: { type: Date, default: Date.now },
});

const refundBookingSchema = new mongoose.Schema({
  bookingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BookingGuest",
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "VacayGuest",
    required: true,
  },
  propertyId: {
    // Adding propertyId reference to the schema
    type: mongoose.Schema.Types.ObjectId,
    ref: "PropertyHost",
    required: true, // Set to true or false based on your requirement
  },
  refundAmount: { type: Number, required: true },
  reason: { type: String, required: true },
  status: { type: String, default: "Pending" },
  timestamp: { type: Date, default: Date.now },
});

const VacayGuest = mongoose.model("VacayGuest", vacayGuestSchema);
const VacayHost = mongoose.model("VacayHost", vacayHostSchema);
const VacayAdmin = mongoose.model("VacayAdmin", vacayAdminSchema);
const PropertyHost = mongoose.model("PropertyHost", propertyHostSchema);
const BookingGuest = mongoose.model("BookingGuest", bookingGuestSchema);
const BookingHistory = mongoose.model("BookingHistory", bookingHistorySchema);
const PropertyRating = mongoose.model("PropertyRating", propertyRatingSchema);
const Refund = mongoose.model("Refund", refundBookingSchema);

// Assuming `VacayAdmin` is a model for managing admin accounts

// Create the first admin account
VacayAdmin.findOne({ email: "vacayAdmin@gmail.com" })
  .then(async (existingAdmin) => {
    if (!existingAdmin) {
      const admin = new VacayAdmin({
        email: "vacayAdmin@gmail.com",
        password: "753951Admin",
      });
      try {
        await admin.save();
        console.log("First admin account created successfully.");
      } catch (saveErr) {
        console.error("Error creating first admin account:", saveErr);
      }
    } else {
      console.log("First admin account already exists.");
    }
  })
  .catch((err) => {
    console.error("Error checking for existing admin:", err);
  });

// Create the second admin account
VacayAdmin.findOne({ email: "admin@vacay.com" })
  .then(async (existingAdmin) => {
    if (!existingAdmin) {
      const admin = new VacayAdmin({
        email: "admin@vacay.com",
        password: "0000",
      });
      try {
        await admin.save();
        console.log("Second admin account created successfully.");
      } catch (saveErr) {
        console.error("Error creating second admin account:", saveErr);
      }
    } else {
      console.log("Second admin account already exists.");
    }
  })
  .catch((err) => {
    console.error("Error checking for existing admin:", err);
  });

app.get("/", function (req, res) {
  res.render("welcome");
});

app.get("/welcome", function (req, res) {
  res.render("loginPage");
});

app.get("/register", function (req, res) {
  res.render("signupMain");
});

app.get("/guestsignup", function (req, res) {
  res.render("signupPage");
});

app.get("/hostsignup", function (req, res) {
  res.render("signupHost");
});

app.get("/loginAdmin", function (req, res) {
  res.render("logAdmin");
});

app.post("/mainAdmin", async function (req, res) {
  const { email, password } = req.body;

  try {
    console.log("Attempting login with:", email, password);

    // Check if the admin credentials are valid
    const admin = await VacayAdmin.findOne({ email, password }).exec();

    console.log("Found admin:", admin);

    if (admin) {
      // Successful login, you can redirect to a dashboard or render another page
      res.render("adminMain");
    } else {
      // Invalid credentials, render login page with an error message
      res.render("logAdmin", { error: "Invalid credentials" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/adminMain", function (req, res) {
  res.render("adminMain");
});

app.get("/login", function (req, res) {
  res.render("loginPage");
});

app.post("/login", async function (req, res) {
  const emailUse = req.body.email;
  const passwordUse = req.body.password;

  console.log(`Attempting to log in with email: ${emailUse}`); // Log the email being used to log in

  try {
    let user, userRole;

    // Check if user is a guest
    const foundVacayGuest = await VacayGuest.findOne({ email: emailUse });

    if (foundVacayGuest) {
      console.log("User found in VacayGuest"); // Log where the user was found
      user = foundVacayGuest;
      userRole = "guest";
    } else {
      // Check if user is a host
      const foundVacayHost = await VacayHost.findOne({ email: emailUse });

      if (foundVacayHost) {
        console.log("User found in VacayHost"); // Log where the user was found
        user = foundVacayHost;
        userRole = "host";
      }
    }

    if (user) {
      const passwordMatch = await bcrypt.compare(passwordUse, user.password);

      if (passwordMatch) {
        console.log("Password match successful"); // Log successful password match

        // Set session for the user
        req.session.user = {
          id: user._id,
          type: userRole,
        };

        console.log("Session after login:", req.session.user); // Log the session

        if (userRole === "guest") {
          res.redirect("/mainView");
        } else if (userRole === "host") {
          res.redirect("/mainHost");
        }
      } else {
        console.log("Password match failed"); // Log failed password match
        res.redirect("/login");
      }
    } else {
      console.log("No user found with this email"); // Log when no user is found
      res.redirect("/login");
    }
  } catch (err) {
    console.error("Error during login:", err); // Log any errors that occur during login
    res.redirect("/login");
  }
});

app.post("/guestSign", async function (req, res) {
  try {
    const hash = await bcrypt.hash(req.body.password, saltRounds);

    const newGuest = new VacayGuest({
      name: req.body.guestName,
      email: req.body.email,
      phoneNum: req.body.phoneNum,
      password: hash,
      type: "Guest",
      userId: (req.session.user && req.session.user.id) || null,
    });

    await newGuest.save();
    res.redirect("/login");
  } catch (err) {
    console.log(err);
    res.redirect("/login");
  }
});

app.post("/hostSign", async function (req, res) {
  try {
    const hash = await bcrypt.hash(req.body.password, saltRounds);

    const newHost = new VacayHost({
      name: req.body.hostName,
      email: req.body.email,
      phoneNum: req.body.phoneNum,
      bankNum: req.body.bankNum,
      password: hash,
      type: "Host",
      userId: (req.session.user && req.session.user.id) || null,
    });

    await newHost.save();
    res.redirect("/mainHost");
  } catch (err) {
    console.log(err);
    res.redirect("/login");
  }
});

app.get("/mainView", async function (req, res) {
  try {
    const propertyHosts = await PropertyHost.find();
    res.render("mainView", { propertyHosts, user: req.session.user });
  } catch (err) {
    console.log(err);
    res.redirect("/login");
  }
});

app.get("/mainHost", async function (req, res) {
  try {
    const propertyHosts = await PropertyHost.find();
    res.render("mainHost", { propertyHosts, user: req.session.user });
  } catch (err) {
    console.log(err);
    res.redirect("/login");
  }
});

app.get("/settingsHost", async function (req, res) {
  const user = req.session.user;

    if (user && user.type === "host") {
      // Assuming you have a VacayGuest model
      const vacayHost = await VacayHost.findOne({ _id: user.id });

      if (vacayHost) {
        res.render("settingHost.ejs", {
          profileName: vacayHost.name,
          profilePic: vacayHost.profilePic,
          // Add other details as needed
        });
      } else {
        // Handle the case when VacayGuest details are not found
        console.log("VacayHost details not found");
        res.status(404).send("VacayHost details not found");
}}});

app.get("/settingsGuest", async function (req, res) {
  const user = req.session.user;

    if (user && user.type === "guest") {
      // Assuming you have a VacayGuest model
      const vacayGuest = await VacayGuest.findOne({ _id: user.id });

      if (vacayGuest) {
        res.render("settingGuest.ejs", {
          profileName: vacayGuest.name,
          profilePic: vacayGuest.profilePic,
          // Add other details as needed
        });
      } else {
        // Handle the case when VacayGuest details are not found
        console.log("VacayGuest details not found");
        res.status(404).send("VacayGuest details not found");
}}});


app.get("/settingsAdmin", function (req, res) {
  res.render("settingAdmin");
});

app.get("/profileGuest", async function (req, res) {
  try {
    // Assuming user details are available in req.session.user
    const user = req.session.user;

    if (user && user.type === "guest") {
      // Assuming you have a VacayGuest model
      const vacayGuest = await VacayGuest.findOne({ _id: user.id });

      if (vacayGuest) {
        res.render("profilePage.ejs", {
          profileName: vacayGuest.name,
          profileEmail: vacayGuest.email,
          profilePhoneNumber: vacayGuest.phoneNum,
          profileStatus: vacayGuest.type,
          profilePic: vacayGuest.profilePic,
        });
        console.log(vacayGuest.profilePic);
      } else {
        // Handle the case when VacayGuest details are not found
        console.log("VacayGuest details not found");
        res.status(404).send("VacayGuest details not found");
      }
    } else {
      // Handle the case when the user doesn't have the required role
      console.log("User doesn't have the required role");
      res.redirect("/login"); // Redirect to login page or handle appropriately
    }
  } catch (error) {
    console.error("Error fetching profile details:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/profileHost", async function (req, res) {
  try {
    // Assuming user details are available in req.session.user
    const user = req.session.user;

    // console.log(req.query); // Use req.query to access query parameters

    if (user && user.type === "host") {
      // Assuming you have a VacayHost model
      const vacayHost = await VacayHost.findOne({ _id: user.id });

      if (vacayHost) {
        res.render("profileHost.ejs", {
          profileName: vacayHost.name,
          profileEmail: vacayHost.email,
          profilePhoneNumber: vacayHost.phoneNum,
          profileStatus: vacayHost.type,
          profilePic: vacayHost.profilePic,
        });
        console.log(vacayHost.profilePic);
      } else {
        // Handle the case when VacayHost details are not found
        console.log("VacayHost details not found");
        res.status(404).send("VacayHost details not found");
      }
    } else {
      // Handle the case when the user doesn't have the required role
      console.log("User doesn't have the required role");
      res.redirect("/login"); // Redirect to login page or handle appropriately
    }
  } catch (error) {
    console.error("Error fetching profile details:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/bookHistory", async function (req, res) {
  try {
    const user = req.session.user;

    if (user && user.type === "guest") {
      // Fetch booking history for the current guest user
      const bookingHistory = await BookingHistory.find({ userId: user.id })
        .populate("propertyId")
        .populate("bookingId");

      res.render("bookingHistory", { bookingHistory });
    } else {
      // Handle the case when the user doesn't have the required role
      console.log("User doesn't have the required role");
      res.redirect("/login"); // Redirect to login page or handle appropriately
    }
  } catch (error) {
    console.error("Error fetching booking history:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/propertyform", function (req, res) {
  res.render("addProp");
});

app.post("/proplist", upload.array("images", 5), async function (req, res) {
  try {
    const newProperty = new PropertyHost({
      name: req.body.propName,
      address: req.body.propAddrs,
      description: req.body.propDesc,
      price: req.body.propPrice,
      guestNum: req.body.propGuest,
      hostId: req.session.user ? req.session.user.id : null,
      images: req.files.map((file) => ({
        data: fs.readFileSync(file.path),
        contentType: file.mimetype,
      })),
    });

    await newProperty.save();
    res.redirect("/propertylist");
  } catch (err) {
    console.log(err);
    res.redirect("/propertylist");
  }
});

app.get("/propertylist", async function (req, res) {
  try {
    const propertyHosts = await PropertyHost.find();
    res.render("propertyList", {
      propertyHosts,
      userId: req.session.user.id.toString(),
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("Error fetching property hosts"); // Send a simple error message
  }
});

app.post("/removeproperty", async function (req, res) {
  const propertyIdToRemove = req.body.propertyId;

  try {
    const removedProperty = await PropertyHost.findByIdAndDelete(
      propertyIdToRemove
    );

    if (removedProperty) {
      console.log("Property removed:", removedProperty);

      const hostId = removedProperty.hostId;
      console.log("Host ID:", hostId);

      const host = await VacayHost.findByIdAndUpdate(
        hostId,
        { $pull: { properties: propertyIdToRemove } },
        { new: true }
      );

      if (host) {
        console.log("Property removed from host:", host);
      } else {
        console.log("Host not found");
      }

      res.redirect("/propertylist");
    } else {
      res.status(404).send("Property not found");
    }
  } catch (err) {
    console.error("Error removing property:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/propertyView/:propertyId", async function (req, res) {
  try {
    const propertyId = req.params.propertyId;
    const property = await PropertyHost.findById(propertyId);

    if (property) {
      res.render("viewProperty", { property: property });
    } else {
      res.status(404).send("Property not found");
    }
  } catch (err) {
    console.error("Error fetching property details:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/bookingProp/:propertyId", async function (req, res) {
  try {
    const propertyId = req.params.propertyId;
    const property = await PropertyHost.findById(propertyId);

    if (property) {
      // Assuming you have a BookingGuest model
      const newBooking = new BookingGuest({
        name: req.body.guestName,
        phoneNum: req.session.user.phoneNum, // Assuming you store user's phone number in the session
        checkin: req.body.checkIn,
        checkout: req.body.checkOut,
        guestNum: req.body.guestNum,
        totalPrice: calculateTotalPrice(
          req.body.checkIn,
          req.body.checkOut,
          property.price
        ),
        bankNo: req.body.bankNo, // Assuming you have a form field for bank number
        bankType: req.body.bankType, // Assuming you have a form field for bank type
      });

      // Save the booking to the database
      await newBooking.save();

      console.log("Booking details:", newBooking);
      console.log("Number of guests:", newBooking.guestNum);

      res.render("paymentGateway", { property, booking: newBooking });
    } else {
      res.status(404).send("Property not found");
    }
  } catch (err) {
    console.error("Error processing booking:", err);
    res.status(500).send("Internal Server Error");
  }
});

function calculateTotalPrice(checkIn, checkOut, price) {
  const checkInDate = new Date(checkIn);
  const checkOutDate = new Date(checkOut);

  // Calculate the number of nights between check-in and check-out
  const timeDifference = checkOutDate.getTime() - checkInDate.getTime();
  const numberOfNights = Math.ceil(timeDifference / (1000 * 3600 * 24));

  // Multiply the number of nights by the nightly rate (property price)
  const totalPrice = numberOfNights * price;

  return totalPrice;
}

app.post("/paymentConfirmation", async function (req, res) {
  try {
    // Fetch the property and booking details from the database
    const propertyId = req.body.propertyId;
    const bookingId = req.body.bookingId;

    // This is just an example, replace it with your actual database queries
    const property = await PropertyHost.findById(propertyId);
    const booking = await BookingGuest.findById(bookingId);

    // Check if property and booking are found
    if (!property || !booking) {
      return res.status(404).send("Property or booking not found");
    }

    // Create a new BookingHistory entry
    const newBookingHistory = new BookingHistory({
      propertyId: property._id,
      bookingId: booking._id,
      userId: req.session.user.id,
    });

    // Save the booking details into the BookingHistory database
    await newBookingHistory.save();

    // Render the bookingList.ejs template with the property and booking details
    res.render("bookingList", {
      property,
      booking,
      bookingHistory: [newBookingHistory],
    });
  } catch (err) {
    console.error("Error fetching property and booking details:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/propVerify", async function (req, res) {
  try {
    // Fetch all PropertyHost data from every VacayHost
    const allPropertyHosts = await PropertyHost.find().populate("hostId");

    // Render the propVerifyList.ejs template with the fetched data
    res.render("propVerifyList", { propertyHosts: allPropertyHosts });
  } catch (error) {
    console.error("Error fetching PropertyHost data:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/logoutAdmin", function (req, res) {
  res.render("welcome");
});

app.get("/guestView", function (req, res) {
  res.redirect("/mainView");
});

app.get("/hostView", function (req, res) {
  res.redirect("/mainHost");
});

app.get("/logout", function (req, res) {
  req.session.destroy(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.get("/aboutUs", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("aboutUs", { userRole: userRole });
});

app.get("/help", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("help", { userRole: userRole });
});

app.get("/policies", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("policies", { userRole: userRole });
});

app.get("/termsCondition", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("termsCondition", { userRole: userRole });
});

app.get("/whyHost", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("whyHost", { userRole: userRole });
});

app.get("/responsibleHost", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("responsibleHost", { userRole: userRole });
});

app.get("/community", function (req, res) {
  let userRole = req.session.user?.type || "unknown"; // Default value

  if (userRole === "unknown") {
    console.log("User role not found in session, redirecting to login page");
    res.redirect("/login");
    return; // Stop execution to prevent further code from running
  }

  // Always passing userRole to the template, ensuring it has a value
  res.render("community", { userRole: userRole });
});

app.get("/editProfile", async function (req, res) {
  try {
    // Assuming user details are available in req.session.user
    const user = req.session.user;

    if (user && user.type === "guest") {
      // Assuming you have a VacayGuest model
      const vacayGuest = await VacayGuest.findOne({ _id: user.id });

      if (vacayGuest) {
        res.render("editProfile.ejs", {
          profileName: vacayGuest.name,
          profileEmail: vacayGuest.email,
          profilePhoneNumber: vacayGuest.phoneNum,
          profileStatus: vacayGuest.type,
          profilePic: vacayGuest.profilePic,
          // Add other details as needed
        });
      } else {
        // Handle the case when VacayGuest details are not found
        console.log("VacayGuest details not found");
        res.status(404).send("VacayGuest details not found");
      }
    } else {
      // Handle the case when the user doesn't have the required role
      console.log("User doesn't have the required role");
      res.redirect("/login"); // Redirect to login page or handle appropriately
    }
  } catch (error) {
    console.error("Error fetching profile details:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/editProfileHost", async function (req, res) {
  try {
    // Assuming user details are available in req.session.user
    const user = req.session.user;

    if (user && user.type === "host") {
      // Assuming you have a  VacayHost model
      const vacayHost = await VacayHost.findOne({ _id: user.id });

      if (vacayHost) {
        res.render("editProfileHost.ejs", {
          profileName: vacayHost.name,
          profileEmail: vacayHost.email,
          profilePhoneNumber: vacayHost.phoneNum,
          profileStatus: vacayHost.type,
          profilePic: vacayHost.profilePic,
          // Add other details as needed
        });
      } else {
        // Handle the case when vacayHostacayHost details are not found
        console.log("VacayHost details not found");
        res.status(404).send("VacayHost details not found");
      }
    } else {
      // Handle the case when the user doesn't have the required role
      console.log("User doesn't have the required role");
      res.redirect("/login"); // Redirect to login page or handle appropriately
    }
  } catch (error) {
    console.error("Error fetching profile details:", error);
    res.status(500).send("Internal Server Error");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

app.post("/editGuestDetails", upload.single('profilePic'), async function (req, res) {
  try {
    const userId = req.session.user.id; // Assuming user ID is stored in session
    const { name, email, phoneNum } = req.body;
    let updateData = { name, email, phoneNum };

    if (req.file) {
      // If a file was uploaded, update the user profile with the new image path
      // For simplicity, storing the path directly; in a real app, you might store a URL or use a cloud storage service
      const profilePicPath = req.file.path;
      updateData.profilePic = profilePicPath;
    }

    console.log("Updating user profile with:", updateData);

    await VacayGuest.findByIdAndUpdate(userId, updateData);

    // Redirect back to the edit profile page or to a success page
    res.redirect("/profileGuest");
  } catch (error) {
    console.error("Error updating profile details:", error);
    res.status(500).send("Internal Server Error");
  }
});


app.post(
  "/editHostDetails",
  upload.single("profilePic"),
  async function (req, res) {
    try {
      const hostId = req.session.user && req.session.user.id; // Assuming the host's ID is stored in session
      if (!hostId) {
        return res.status(401).send("User not logged in");
      }

      const updateData = {
        name: req.body.name,
        email: req.body.email,
        phoneNum: req.body.phoneNum,
      };

      if (req.file) {
        updateData.profilePic = req.file.path; // Save the path of the uploaded file
      }

      await VacayHost.findByIdAndUpdate(hostId, updateData);

      res.redirect("/profileHost");
    } catch (err) {
      console.log(err);
      res.redirect("/editProfileHost"); // Assuming you have a route for editing profiles
    }
  }
);

app.get("/propRating/:bookingHistoryId", async function (req, res) {
  const bookingHistoryId = req.params.bookingHistoryId;
  console.log("Fetching booking history for ID:", bookingHistoryId);
  
  try {
    const bookingHistory = await BookingHistory.findById(bookingHistoryId)
      .populate("propertyId")
      .populate("userId");

    console.log("Booking History:", bookingHistory);
      
    if (!bookingHistory || !bookingHistory.propertyId) {
      return res.status(404).send("Booking history not found or property not associated");
    }
    
    const existingRating = await PropertyRating.findOne({
      userId: bookingHistory.userId,
      propertyId: bookingHistory.propertyId
    });

    console.log("Existing Rating:", existingRating);
    
    if (existingRating) {
      // Rating exists, pass it to the template to display it instead of the form
      res.render("propRatingView", { propertyHost: bookingHistory.propertyId, userId: bookingHistory.userId._id, existingRating });
    } else {
      // No existing rating, render form to allow rating
      res.render("propRating", { propertyHost: bookingHistory.propertyId, userId: bookingHistory.userId._id });
    }
  } catch (error) {
    console.error("An error occurred:", error);
    res.status(500).send("An internal server error occurred");
}
}
);


// POST route to create a new rating
app.post("/ratings/:propertyId", async function (req, res) {
  const propertyId = req.params.propertyId;
  const property = await PropertyHost.findById(propertyId);

  const newRating = new PropertyRating({
    propertyId: req.body.propertyId,
    userId: req.body.userId,
    rating: req.body.rating,
    review: req.body.review,
  });

  try {
    const savedRating = await newRating.save();
    res.redirect("/bookHistory");
  } catch (err) {
    res.status(400).send("Bad Request");
  }
});

app.get("/refundGuest/:bookingHistoryId", async function (req, res) {
  const bookingHistoryId = req.params.bookingHistoryId;
  console.log("Fetching booking history for ID:", bookingHistoryId);

  try {
    // Check if there's an existing refund request for the bookingHistoryId
    const existingRefund = await Refund.findOne({
      bookingId: bookingHistoryId,
    });
    if (existingRefund) {
      // If a refund request exists, render a message instead of the form
      return res.render("refundStatus", {
        message:
          "A refund request has already been submitted for this booking.",
      });
    }

    // If no refund request exists, proceed to fetch the booking details
    const bookingHistory = await BookingHistory.findById(
      bookingHistoryId
    ).populate("propertyId");

    // Fetch the booking guest from the database
    const bookingGuest = await BookingGuest.findById(bookingHistory.bookingId);

    // Check if bookingHistory and bookingGuest were successfully fetched before proceeding
    if (!bookingHistory || !bookingGuest) {
      // Handle the case where the booking details could not be found
      return res.status(404).send("Booking details not found.");
    }

    // Render the refundGuest view with the booking details and booking guest details
    res.render("refundGuest", { bookingHistory, bookingGuest });
  } catch (error) {
    console.error(
      "Error fetching booking details or checking refund status:",
      error
    );
    res
      .status(500)
      .send({ error: "An error occurred while processing your request." });
  }
});

app.post("/refund", async function (req, res) {
  // Extract refund details from the request body
  const { bookingId, userId, reason, totalPrice } = req.body;

  // Fetch the booking details from the database
  const bookingHistory = await BookingHistory.findById(bookingId).populate(
    "propertyId"
  );

  // Fetch the booking guest from the database
  const bookingGuest = await BookingGuest.findById(bookingHistory.bookingId);

  // Check if the booking exists
  if (!bookingGuest) {
    return res.status(404).send({ error: "Booking not found." });
  }

  const propertyId = bookingHistory.propertyId._id;

  // Create a new refund
  const refund = new Refund({
    bookingId,
    userId,
    propertyId, // Now including propertyId in the refund
    refundAmount: totalPrice, // use the totalPrice from the form as the refundAmount
    reason,
    status: "Pending", // status is always "Pending" when a refund is first created
  });

  console.log("Refund Details:", refund);

  try {
    // Save the refund to the database
    await refund.save();
    console.log("Refund Saved Succesfully");
    // Send a success response
    res.redirect("/bookHistory");
  } catch (error) {
    console.error("Error saving refund:", error);
    res.status(500).send({
      error: "An error occurred while creating the refund request.",
      details: error.message,
    });
  }
});

app.get("/refundListGuest", async function (req, res) {
  if (!req.session.user || !req.session.user.id) {
    return res.redirect("/login");
  }

  const userId = req.session.user.id;

  try {
    const refundList = await Refund.find({ userId: userId })
      .populate("bookingId")
      .populate("userId")
      .populate("propertyId") // Populate propertyId to access property details
      .exec();

    console.log("Refund List:", refundList);

    res.render("refundListGuest", { Refund: refundList });
  } catch (error) {
    console.error("Error fetching refund requests", error);
    res.status(500).send("Error fetching refund requests");
  }
});

// Route to handle search
app.get("/search", async function (req, res) {
  const { location, numGuest, checkIn, checkOut } = req.query;

  // Call the search function here (implement it in the next step)
  try {
    const availableProperties = await searchProperties(
      location,
      numGuest,
      checkIn,
      checkOut
    );
    res.render("searchResults", { properties: availableProperties }); // Assuming you have a view called 'searchResults'
  } catch (error) {
    console.error("Search Error:", error);
    res.status(500).send("Server error during property search.");
  }
});

const searchProperties = async (location, numGuest, checkIn, checkOut) => {
  const checkInDate = new Date(checkIn);
  const checkOutDate = new Date(checkOut);

  // Find properties that match the location and guest number criteria
  let initialProperties = await PropertyHost.find({
    address: new RegExp(location, "i"), // Case-insensitive search for location
    guestNum: { $gte: Number(numGuest) }, // Greater than or equal to numGuest
  });

  // Find bookings that are within the requested date range
  const conflictingBookings = await BookingHistory.find({
    $or: [
      { checkin: { $lt: checkOutDate, $gte: checkInDate } }, // Check-in within range
      { checkout: { $lte: checkOutDate, $gt: checkInDate } }, // Check-out within range
      { checkin: { $lte: checkInDate }, checkout: { $gte: checkOutDate } }, // Encompasses the range
    ],
  });

  // Extract property IDs from conflicting bookings
  const bookedPropertyIds = conflictingBookings.map((booking) =>
    booking.propertyId.toString()
  );

  // Filter initialProperties to exclude properties with conflicting bookings
  const availableProperties = initialProperties.filter(
    (property) => !bookedPropertyIds.includes(property._id.toString())
  );

  return availableProperties;
};

app.get("/settlerefund", async function (req, res) {
  try {
    // Initialize userRole with a default value
    let userRole = "guest"; // Assuming 'guest' as default, adjust as necessary

    // Fetch all refunds and populate the property details
    const refunds = await Refund.find({}).populate("propertyId").exec();

    // Check if user session exists and the user type is 'host'
    if (req.session.user && req.session.user.type === "host") {
      const user = req.session.user; // Use the user from the session

      // Fetch host details based on the session user ID
      const vacayHost = await VacayHost.findOne({ _id: user.id });

      // If a matching host is found, adjust the user role
      if (vacayHost) {
        userRole = "host";
      }
    }

    console.log("User Role:", userRole);

    // Pass the user role and refunds to the EJS template
    res.render("settleRefund", { refunds, userRole, messages: req.flash() });
  } catch (error) {
    console.error("Error fetching refunds:", error);
    res.status(500).send("Internal Server Error");
  }
});


// Route for accepting a refund
app.post("/acceptrefund/:refundId", async (req, res) => {
  const { refundId } = req.params;
  try {
    // Find the refund by its ID and update its status to "Accepted"
    await Refund.findByIdAndUpdate(refundId, { status: "Accepted" });
    req.flash("successAccept", "Refund Accepted Successfully");
    res.redirect("/settlerefund");
  } catch (error) {
    console.error("Error accepting refund:", error);
    res
      .status(500)
      .send({ error: "An error occurred while accepting the refund request." });
  }
});

// Route for rejecting a refund
app.post("/rejectrefund/:refundId", async (req, res) => {
  const { refundId } = req.params;
  try {
    // Find the refund by its ID and update its status to "Rejected"
    await Refund.findByIdAndUpdate(refundId, { status: "Rejected" });
    req.flash("successReject", "Refund Rejected Successfully");
    res.redirext("/settlerefund");
  } catch (error) {
    console.error("Error rejecting refund:", error);
    res
      .status(500)
      .send({ error: "An error occurred while rejecting the refund request." });
  }
});

app.get("/propertyRatings", async function (req, res) {
  try {
    // Assuming you have a way to identify the current user's ID (e.g., from session or token)
    // and that the current user is a host.
    const hostId = req.session.user.id; // or however you're storing/accessing the logged-in user's ID
    console.log("Host ID:", hostId);

    // First, find all properties owned by the current host
    const properties = await PropertyHost.find({ hostId: hostId });
    console.log("Properties:", properties);

    // Extract property IDs to use in querying ratings
    const propertyIds = properties.map((property) => property._id);
    console.log("Property IDs:", propertyIds);

    // Fetch all ratings for these properties and populate necessary details
    const propertyRatings = await PropertyRating.find({
      propertyId: { $in: propertyIds },
    })
      .populate("propertyId") // Populates the property details
      .populate("userId", "name") // Populates the user details, assuming you want to show the user's name
      .exec();

    // Since we now have property ratings with populated details, we can pass these directly to the EJS template
    res.render("propertyRatings", { propertyRatings });
  } catch (error) {
    console.error("Error fetching property ratings:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/financialReport", async function (req, res) {
  try {
    const hostId = req.session.user.id;
    const properties = await PropertyHost.find({ hostId: hostId });
    const propertyIds = properties.map((property) => property._id);

    let revenueData = [];

    for (const propertyId of propertyIds) {
      const bookings = await BookingHistory.aggregate([
        { $match: { propertyId: propertyId } },
        { $lookup: {
            from: "bookingguests", // The collection to join with, ensure this name matches your MongoDB collection name for BookingGuest documents
            localField: "bookingId", // Field from BookingHistory
            foreignField: "_id", // Corresponding field in BookingGuest
            as: "bookingInfo" // The array to populate with the result of the join
          }
        },
        { $unwind: "$bookingInfo" }, // Deconstructs the bookingInfo array
        { $group: {
            _id: "$propertyId",
            totalRevenue: { $sum: "$bookingInfo.totalPrice" },
            bookingCount: { $sum: 1 }
          }
        },
      ]);

      if (bookings.length > 0) {
        const propertyInfo = properties.find((p) => p._id.equals(propertyId));
        revenueData.push({
          propertyName: propertyInfo.name,
          bookingCount: bookings[0].bookingCount,
          totalRevenue: bookings[0].totalRevenue,
        });
      }
    }

    res.render("financialReport", { revenueData });
  } catch (error) {
    console.error("Error fetching revenue data:", error);
    res.status(500).send("Internal Server Error");
  }
});

