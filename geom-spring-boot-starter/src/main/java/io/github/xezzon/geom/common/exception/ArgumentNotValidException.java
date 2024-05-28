package io.github.xezzon.geom.common.exception;

import io.github.xezzon.tao.exception.ClientException;
import java.util.stream.Collectors;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;

/**
 * @author xezzon
 */
public class ArgumentNotValidException extends ClientException {

  public ArgumentNotValidException(MethodArgumentNotValidException e) {
    super(
        ErrorCode.ARGUMENT_NOT_VALID.code(),
        e.getAllErrors().parallelStream()
            .map(ObjectError::getDefaultMessage)
            .collect(Collectors.joining("\n")),
        e
    );
  }
}
