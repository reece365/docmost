import { z } from "zod/v4";
import { useForm } from "@mantine/form";
import { zod4Resolver } from "mantine-form-zod-resolver";
import useAuth from "@/features/auth/hooks/use-auth";
import {
  Container,
  Title,
  TextInput,
  Button,
  PasswordInput,
  Box,
  Anchor,
  Group,
  Divider,
  Alert,
} from "@mantine/core";
import classes from "./auth.module.css";
import { useRedirectIfAuthenticated } from "@/features/auth/hooks/use-redirect-if-authenticated.ts";
import { Link, useSearchParams } from "react-router-dom";
import APP_ROUTE, { getRedirectParam } from "@/lib/app-route.ts";
import { useTranslation } from "react-i18next";
import SsoLogin from "@/ee/components/sso-login.tsx";
import { useWorkspacePublicDataQuery } from "@/features/workspace/queries/workspace-query.ts";
import { Error404 } from "@/components/ui/error-404.tsx";
import React from "react";
import { AuthLayout } from "./auth-layout.tsx";
import { IconBrandSlack } from "@tabler/icons-react";

const formSchema = z.object({
  email: z
    .email()
    .min(1, { message: "email is required" }),
  password: z.string().min(1, { message: "Password is required" }),
});
type FormValues = z.infer<typeof formSchema>;

export function LoginForm() {
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const { signIn, isLoading } = useAuth();
  useRedirectIfAuthenticated();
  const {
    data,
    isLoading: isDataLoading,
    isError,
    error,
  } = useWorkspacePublicDataQuery();

  const form = useForm<FormValues>({
    validate: zod4Resolver(formSchema),
    initialValues: {
      email: "",
      password: "",
    },
  });

  async function onSubmit(data: FormValues) {
    await signIn(data);
  }

  function onSlackSignIn() {
    const redirect = getRedirectParam();
    const query = redirect ? `?redirect=${encodeURIComponent(redirect)}` : "";
    window.location.href = `/api/auth/slack${query}`;
  }

  const slackError = searchParams.get("slackError");
  const slackErrorMessages: Record<string, string> = {
    access_denied: t("Slack sign-in was canceled."),
    email_required: t("Slack did not provide an email for your account."),
    authentication_failed: t("Unable to sign in with Slack. Please try again."),
  };
  const slackErrorMessage = slackError ? slackErrorMessages[slackError] : null;

  if (isDataLoading) {
   return null;
  }

  if (isError && error?.["response"]?.status === 404) {
    return <Error404 />;
  }

  return (
    <AuthLayout>
      <Container size={420} className={classes.container}>
        <Box p="xl" className={classes.containerBox}>
          <Title order={2} ta="center" fw={500} mb="md">
            {t("Login")}
          </Title>

          {slackErrorMessage && (
            <Alert color="red" mb="md">
              {slackErrorMessage}
            </Alert>
          )}

          <SsoLogin />

          {data?.slackAuthEnabled && (
            <>
              <Button
                onClick={onSlackSignIn}
                leftSection={<IconBrandSlack size={16} />}
                variant="default"
                fullWidth
              >
                {t("Sign in with Slack")}
              </Button>
              {!data?.enforceSso && (
                <Divider my="xs" label="OR" labelPosition="center" />
              )}
            </>
          )}

          {!data?.enforceSso && (
            <>
              <form onSubmit={form.onSubmit(onSubmit)}>
                <TextInput
                  id="email"
                  type="email"
                  label={t("Email")}
                  placeholder="email@example.com"
                  variant="filled"
                  {...form.getInputProps("email")}
                />

                <PasswordInput
                  label={t("Password")}
                  placeholder={t("Your password")}
                  variant="filled"
                  mt="md"
                  {...form.getInputProps("password")}
                />

                <Group justify="flex-end" mt="sm">
                  <Anchor
                    to={APP_ROUTE.AUTH.FORGOT_PASSWORD}
                    component={Link}
                    underline="never"
                    size="sm"
                  >
                    {t("Forgot your password?")}
                  </Anchor>
                </Group>

                <Button type="submit" fullWidth mt="md" loading={isLoading}>
                  {t("Sign In")}
                </Button>
              </form>
            </>
          )}
        </Box>
      </Container>
    </AuthLayout>
  );
}
