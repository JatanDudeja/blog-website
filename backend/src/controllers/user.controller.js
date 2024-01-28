import { asyncHandler } from "../utils/asyncHandler.js";
import { APIErrors } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { APIResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = await user.generateAccessToken();
    const newRefreshToken = await user.generateRefreshToken();

    user.refreshToken = newRefreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, newRefreshToken };
  } catch (error) {
    throw new APIErrors(
      500,
      "Something went wrong while generating refresh and access token."
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if (
    [email, username, password].some((field) => {
      return field?.trim() === "";
    })
  ) {
    throw new APIErrors(400, "All fields are required.");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new APIErrors(409, "User with email or username already exists.");
  }

  const user = await User.create({
    email,
    password,
    username: username.toLowerCase(),
  });

  const isCreatedUser = await User.findById(user?._id).select(
    "-password -refreshToken"
  );

  if (!isCreatedUser) {
    throw new APIErrors(
      500,
      "Something went wrong while registering the user."
    );
  }

  return res
    .status(201)
    .json(new APIResponse(200, isCreatedUser, "User Registered Successfully."));
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if (!username || !email) {
    throw new APIErrors(400, "Username or email is required.");
  }

  const user = await User.findOne({ $or: [{ username }, { email }] });

  if (!user) throw new APIErrors(404, "User does not exist.");

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) throw new APIErrors(401, "Invalid Credentials!");

  const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new APIResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken : newRefreshToken,
        },
        "User logged in successfully."
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true, // the new updated value of this field gets returned.
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new APIResponse(200, {}, "User logged out successfully."));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
  
    if (!incomingRefreshToken) {
      throw new APIErrors(401, "Unauthorized request.");
    }
  
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
  
    const user = await User.findById(decodedToken?._id);
  
    if (!user) {
      throw new APIErrors(401, "Invalid refresh token");
    }
  
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new APIErrors(401, "Refresh Token is expired or used.");
    }
  
    const options = {
      httpOnly: true,
      secure: true,
    };
  
    const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );
  
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new APIResponse(
          200,
          {
            accessToken,
            refreshToken : newRefreshToken,
          },
          "Access token refreshed successfully."
        )
      );
  } catch (error) {
    throw new APIErrors(401, error?.message)
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body

  const user = await User.findById(req.user?._id)

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
  if(!isPasswordCorrect){
    throw new APIErrors(400, "Invalid old password.")
  }

  user.password = newPassword;

  await user.save({validateBeforeSave: false})

  return res
  .status(200)
  .json(new APIResponse(200, {}, "Password Changed!"))

})


const getCurrectUser = asyncHandler(async (req, res) => {
  return res
  .status(200)
  .json(new APIResponse(200, req.user, "Current user fetched successfully."))
})

const updateAccount = asyncHandler(async (req, res) =>{
  const {email } = req.body

  if(!email){
    throw new APIErrors(400, "All fields are required.")
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        email
      }
    },
    {new : true}
  ).select("-password")

  return res
  .status(200)
  .json(new APIResponse(200, user,"Account details updated successfully."))

})


export { registerUser, loginUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrectUser, updateAccount };
