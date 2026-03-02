import axios from "axios";

interface ErrorPayload {
  error?: string;
}

export function getErrorMessage(error: unknown): string {
  if (axios.isAxiosError<ErrorPayload>(error)) {
    const responseMessage = error.response?.data?.error;
    if (responseMessage) {
      return responseMessage;
    }
    if (error.message) {
      return error.message;
    }
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unknown error";
}
